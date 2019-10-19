// Copyright (c) 2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

//////////////////////////
#include <rpc/RpcServer.h>
//////////////////////////

#include <iostream>

#include "version.h"

#include <errors/ValidateParameters.h>
#include <logger/Logger.h>
#include <serialization/SerializationTools.h>
#include <utilities/Addresses.h>
#include <utilities/ColouredMsg.h>
#include <utilities/FormatTools.h>
#include <utilities/ParseExtra.h>

RpcServer::RpcServer(
    const uint16_t bindPort,
    const std::string rpcBindIp,
    const std::string corsHeader,
    const std::string feeAddress,
    const uint64_t feeAmount,
    const RpcMode rpcMode,
    const std::shared_ptr<CryptoNote::Core> core,
    const std::shared_ptr<CryptoNote::NodeServer> p2p,
    const std::shared_ptr<CryptoNote::ICryptoNoteProtocolHandler> syncManager):
    m_port(bindPort),
    m_host(rpcBindIp),
    m_corsHeader(corsHeader),
    m_feeAddress(feeAddress),
    m_feeAmount(feeAmount),
    m_rpcMode(rpcMode),
    m_core(core),
    m_p2p(p2p),
    m_syncManager(syncManager)
{
    if (m_feeAddress != "")
    {
        Error error = validateAddresses({m_feeAddress}, false);

        if (error != SUCCESS)
        {
            std::cout << WarningMsg("Fee address given is not valid: " + error.getErrorMessage()) << std::endl;
            exit(1);
        }
    }

    const bool bodyRequired = true;
    const bool bodyNotRequired = false;

    /* Route the request through our middleware function, before forwarding
       to the specified function */
    const auto router = [this](const auto function, const RpcMode routePermissions, const bool isBodyRequired) {
        return [=](const httplib::Request &req, httplib::Response &res) {
            /* Pass the inputted function with the arguments passed through
               to middleware */
            middleware(
                req,
                res,
                routePermissions,
                isBodyRequired,
                std::bind(function, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3)
            );
        };
    };

    const auto jsonRpc = [this, router](const auto &req, auto &res) {
        const auto body = getJsonBody(req, res, true);

        if (!body)
        {
            return;
        }

        if (!hasMember(*body, "method"))
        {
            failRequest(400, "Missing JSON parameter: 'method'", res);
            return;
        }

        const auto method = getStringFromJSON(*body, "method");

        if (method == "getblocktemplate")
        {
            router(&RpcServer::getBlockTemplate, RpcMode::Default, bodyRequired)(req, res);
        }
        else if (method == "submitblock")
        {
            router(&RpcServer::submitBlock, RpcMode::Default, bodyRequired)(req, res);
        }
        else if (method == "getblockcount")
        {
            router(&RpcServer::getBlockCount, RpcMode::Default, bodyNotRequired)(req, res);
        }
        else
        {
            res.status = 404;
        }
    };

    m_server.Get("/json_rpc", jsonRpc)
            .Get("/info", router(&RpcServer::info, RpcMode::Default, bodyNotRequired))
            .Get("/fee", router(&RpcServer::fee, RpcMode::Default, bodyNotRequired))
            .Get("/height", router(&RpcServer::height, RpcMode::Default, bodyNotRequired))
            .Get("/peers", router(&RpcServer::peers, RpcMode::Default, bodyNotRequired))

            .Post("/json_rpc", jsonRpc)
            .Post("/sendrawtransaction", router(&RpcServer::sendTransaction, RpcMode::Default, bodyRequired))
            .Post("/getrandom_outs", router(&RpcServer::getRandomOuts, RpcMode::Default, bodyRequired))
            .Post("/getwalletsyncdata", router(&RpcServer::getWalletSyncData, RpcMode::Default, bodyRequired))
            .Post("/get_global_indexes_for_range", router(&RpcServer::getGlobalIndexes, RpcMode::Default, bodyRequired))

            /* Matches everything */
            /* NOTE: Not passing through middleware */
            .Options(".*", [this](auto &req, auto &res) { handleOptions(req, res); });
}

RpcServer::~RpcServer()
{
    stop();
}

void RpcServer::start()
{
    m_serverThread = std::thread(&RpcServer::listen, this);
}

void RpcServer::listen()
{
    const auto listenError = m_server.listen(m_host, m_port);

    if (listenError != httplib::SUCCESS)
    {
        std::cout << WarningMsg("Failed to start RPC server: ")
                  << WarningMsg(httplib::detail::getSocketErrorMessage(listenError)) << std::endl;
        exit(1);
    }
}

void RpcServer::stop()
{
    m_server.stop();

    if (m_serverThread.joinable())
    {
        m_serverThread.join();
    }
}

std::tuple<std::string, uint16_t> RpcServer::getConnectionInfo()
{
    return {m_host, m_port};
}

std::optional<rapidjson::Document> RpcServer::getJsonBody(
    const httplib::Request &req,
    httplib::Response &res,
    const bool bodyRequired)
{
    rapidjson::Document jsonBody;

    if (!bodyRequired)
    {
        return jsonBody;
    }

    if (jsonBody.Parse(req.body.c_str()).HasParseError())
    {
        std::stringstream stream;

        if (!req.body.empty())
        {
            stream << "Warning: received body is not JSON encoded!\n"
                   << "Key/value parameters are NOT supported.\n"
                   << "Body:\n" << req.body;

            Logger::logger.log(
                stream.str(),
                Logger::INFO,
                { Logger::DAEMON_RPC }
            );
        }

        stream << "Failed to parse request body as JSON";

        failRequest(400, stream.str(), res);

        return std::nullopt;
    }

    return jsonBody;
}

void RpcServer::middleware(
    const httplib::Request &req,
    httplib::Response &res,
    const RpcMode routePermissions,
    const bool bodyRequired,
    std::function<std::tuple<Error, uint16_t>(
        const httplib::Request &req,
        httplib::Response &res,
        const rapidjson::Document &body)> handler)
{
    Logger::logger.log(
        "Incoming " + req.method + " request: " + req.path,
        Logger::DEBUG,
        { Logger::DAEMON_RPC }
    );

    if (m_corsHeader != "")
    {
        res.set_header("Access-Control-Allow-Origin", m_corsHeader);
    }
    
    const auto jsonBody = getJsonBody(req, res, bodyRequired);

    if (!jsonBody)
    {
        return;
    }

    /* If this route requires higher permissions than we have enabled, then
     * reject the request */
    if (routePermissions > m_rpcMode)
    {
        std::stringstream stream;

        stream << "You do not have permission to access this method. Please "
                  "relaunch your daemon with the --enable-blockexplorer";

        if (routePermissions == RpcMode::AllMethodsEnabled)
        {
            stream << "-detailed";
        }

        stream << " command line option to access this method.";

        failRequest(403, stream.str(), res);

        return;
    }

    try
    {
        const auto [error, statusCode] = handler(req, res, *jsonBody);

        if (error)
        {
            rapidjson::StringBuffer sb;
            rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

            writer.StartObject();

            writer.Key("errorCode");
            writer.Uint(error.getErrorCode());

            writer.Key("errorMessage");
            writer.String(error.getErrorMessage());

            writer.EndObject();

            res.set_content(sb.GetString(), "application/json");
            res.status = 400;
        }
        else
        {
            res.status = statusCode;
        }

        return;
    }
    catch (const std::invalid_argument &e)
    {
        Logger::logger.log(
            "Caught JSON exception, likely missing required json parameter: " + std::string(e.what()),
            Logger::FATAL,
            { Logger::DAEMON_RPC }
        );

        failRequest(400, e.what(), res);
    }
    catch (const std::exception &e)
    {
        Logger::logger.log(
            "Caught unexpected exception: " + std::string(e.what()),
            Logger::FATAL,
            { Logger::DAEMON_RPC }
        );

        failRequest(500, "Internal server error: " + std::string(e.what()), res);
    }
}

void RpcServer::failRequest(uint16_t statusCode, std::string body, httplib::Response &res)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    writer.Key("status");
    writer.String("Failed");

    writer.Key("error");
    writer.String(body);

    writer.EndObject();

    res.set_content(sb.GetString(), "application/json");
    res.status = statusCode;
}

void RpcServer::failJsonRpcRequest(
    const int64_t errorCode,
    const std::string errorMessage,
    httplib::Response &res)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();
    {
        writer.Key("jsonrpc");
        writer.String("2.0");

        writer.Key("error");
        writer.StartObject();
        {
            writer.Key("message");
            writer.String(errorMessage);

            writer.Key("code");
            writer.Int64(errorCode);
        }
        writer.EndObject();
    }
    writer.EndObject();

    res.set_content(sb.GetString(), "application/json");
    res.status = 200;
}

void RpcServer::handleOptions(const httplib::Request &req, httplib::Response &res) const
{
    Logger::logger.log(
        "Incoming " + req.method + " request: " + req.path,
        Logger::DEBUG,
        { Logger::DAEMON_RPC }
    );

    std::string supported = "OPTIONS, GET, POST";

    if (m_corsHeader == "")
    {
        supported = "";
    }

    if (req.has_header("Access-Control-Request-Method"))
    {
        res.set_header("Access-Control-Allow-Methods", supported);
    }
    else
    {
        res.set_header("Allow", supported);
    }

    if (m_corsHeader != "")
    {
        res.set_header("Access-Control-Allow-Origin", m_corsHeader);
        res.set_header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, X-API-KEY");
    }

    res.status = 200;
}

std::tuple<Error, uint16_t> RpcServer::info(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    const uint64_t height = m_core->getTopBlockIndex() + 1;
    const uint64_t networkHeight = std::max(1u, m_syncManager->getBlockchainHeight());
    const auto blockDetails = m_core->getBlockDetails(height - 1);
    const uint64_t difficulty = m_core->getDifficultyForNextBlock();

    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    writer.Key("height");
    writer.Uint64(height);

    writer.Key("difficulty");
    writer.Uint64(difficulty);

    writer.Key("tx_count");
    /* Transaction count without coinbase transactions - one per block, so subtract height */
    writer.Uint64(m_core->getBlockchainTransactionCount() - height);

    writer.Key("tx_pool_size");
    writer.Uint64(m_core->getPoolTransactionCount());

    writer.Key("alt_blocks_count");
    writer.Uint64(m_core->getAlternativeBlockCount());

    uint64_t total_conn = m_p2p->get_connections_count();
    uint64_t outgoing_connections_count = m_p2p->get_outgoing_connections_count();

    writer.Key("outgoing_connections_count");
    writer.Uint64(outgoing_connections_count);

    writer.Key("incoming_connections_count");
    writer.Uint64(total_conn - outgoing_connections_count);

    writer.Key("white_peerlist_size");
    writer.Uint64(m_p2p->getPeerlistManager().get_white_peers_count());

    writer.Key("grey_peerlist_size");
    writer.Uint64(m_p2p->getPeerlistManager().get_gray_peers_count());

    writer.Key("last_known_block_index");
    writer.Uint64(std::max(1u, m_syncManager->getObservedHeight()) - 1);

    writer.Key("network_height");
    writer.Uint64(networkHeight);

    writer.Key("upgrade_heights");
    writer.StartArray();
    {
        for (const uint64_t height : CryptoNote::parameters::FORK_HEIGHTS)
        {
            writer.Uint64(height);
        }
    }
    writer.EndArray();

    writer.Key("supported_height");
    writer.Uint64(CryptoNote::parameters::FORK_HEIGHTS_SIZE == 0
        ? 0
        : CryptoNote::parameters::FORK_HEIGHTS[CryptoNote::parameters::CURRENT_FORK_INDEX]);

    writer.Key("hashrate");
    writer.Uint64(round(difficulty / CryptoNote::parameters::DIFFICULTY_TARGET));

    writer.Key("synced");
    writer.Bool(height == networkHeight);

    writer.Key("major_version");
    writer.Uint64(blockDetails.majorVersion);

    writer.Key("minor_version");
    writer.Uint64(blockDetails.minorVersion);

    writer.Key("version");
    writer.String(PROJECT_VERSION);

    writer.Key("status");
    writer.String("OK");

    writer.Key("start_time");
    writer.Uint64(m_core->getStartTime());

    writer.EndObject();

    res.set_content(sb.GetString(), "application/json");

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::fee(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    writer.Key("address");
    writer.String(m_feeAddress);

    writer.Key("amount");
    writer.Uint64(m_feeAmount);

    writer.Key("status");
    writer.String("OK");

    writer.EndObject();

    res.set_content(sb.GetString(), "application/json");

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::height(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    writer.Key("height");
    writer.Uint64(m_core->getTopBlockIndex() + 1);

    writer.Key("network_height");
    writer.Uint64(std::max(1u, m_syncManager->getBlockchainHeight()));

    writer.Key("status");
    writer.String("OK");

    writer.EndObject();

    res.set_content(sb.GetString(), "application/json");

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::peers(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    std::list<PeerlistEntry> peers_white;
    std::list<PeerlistEntry> peers_gray;

    m_p2p->getPeerlistManager().get_peerlist_full(peers_gray, peers_white);

    writer.Key("peers");
    writer.StartArray();
    {
        for (const auto &peer : peers_white)
        {
            std::stringstream stream;
            stream << peer.adr;
            writer.String(stream.str());
        }
    }
    writer.EndArray();

    writer.Key("peers_gray");
    writer.StartArray();
    {
        for (const auto &peer : peers_gray)
        {
            std::stringstream stream;
            stream << peer.adr;
            writer.String(stream.str());
        }
    }
    writer.EndArray();

    writer.Key("status");
    writer.String("OK");

    writer.EndObject();

    res.set_content(sb.GetString(), "application/json");

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::sendTransaction(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    std::vector<uint8_t> transaction;

    const std::string rawData = getStringFromJSON(body, "tx_as_hex");

    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    if (!Common::fromHex(rawData, transaction))
    {
        writer.Key("status");
        writer.String("Failed");

        writer.Key("error");
        writer.String("Failed to parse transaction from hex buffer");
    }
    else
    {
        Crypto::Hash transactionHash = Crypto::cn_fast_hash(transaction.data(), transaction.size());

        writer.Key("transactionHash");
        writer.String(Common::podToHex(transactionHash));

        std::stringstream stream;

        stream << "Attempting to add transaction " << transactionHash << " from /sendrawtransaction to pool";

        Logger::logger.log(
            stream.str(),
            Logger::DEBUG,
            { Logger::DAEMON_RPC }
        );

        const auto [success, error] = m_core->addTransactionToPool(transaction);

        if (!success)
        {
            /* Empty stream */
            std::stringstream().swap(stream);

            stream << "Failed to add transaction " << transactionHash << " from /sendrawtransaction to pool: " << error;

            Logger::logger.log(
                stream.str(),
                Logger::INFO,
                { Logger::DAEMON_RPC }
            );

            writer.Key("status");
            writer.String("Failed");

            writer.Key("error");
            writer.String(error);
        }
        else
        {
            m_syncManager->relayTransactions({transaction});

            writer.Key("status");
            writer.String("OK");

            writer.Key("error");
            writer.String("");

        }
    }

    writer.EndObject();

    res.set_content(sb.GetString(), "application/json");
    
    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::getRandomOuts(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    const uint64_t numOutputs = getUint64FromJSON(body, "outs_count");

    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    writer.Key("outs");

    writer.StartArray();
    {
        for (const auto &jsonAmount : getArrayFromJSON(body, "amounts"))
        {
            writer.StartObject();

            const uint64_t amount = jsonAmount.GetUint64();

            std::vector<uint32_t> globalIndexes;
            std::vector<Crypto::PublicKey> publicKeys;

            const auto [success, error] = m_core->getRandomOutputs(
                amount, static_cast<uint16_t>(numOutputs), globalIndexes, publicKeys
            );

            if (!success)
            {
                return {Error(CANT_GET_FAKE_OUTPUTS, error), 200};
            }

            if (globalIndexes.size() != numOutputs)
            {
                std::stringstream stream;

                stream << "Failed to get enough matching outputs for amount " << amount << " ("
                       << Utilities::formatAmount(amount) << "). Requested outputs: " << numOutputs
                       << ", found outputs: " << globalIndexes.size()
                       << ". Further explanation here: https://gist.github.com/zpalmtree/80b3e80463225bcfb8f8432043cb594c"
                       << std::endl
                       << "Note: If you are a public node operator, you can safely ignore this message. "
                       << "It is only relevant to the user sending the transaction.";

                return {Error(CANT_GET_FAKE_OUTPUTS, stream.str()), 200};
            }

            writer.Key("amount");
            writer.Uint64(amount);

            writer.Key("outs");
            writer.StartArray();
            {
                for (size_t i = 0; i < globalIndexes.size(); i++)
                {
                    writer.StartObject();
                    {
                        writer.Key("global_amount_index");
                        writer.Uint64(globalIndexes[i]);

                        writer.Key("out_key");
                        writer.String(Common::podToHex(publicKeys[i]));
                    }
                    writer.EndObject();
                }
            }
            writer.EndArray();

            writer.EndObject();
        }
    }
    writer.EndArray();

    writer.Key("status");
    writer.String("OK");

    writer.EndObject();

    res.set_content(sb.GetString(), "application/json");

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::getWalletSyncData(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    std::vector<Crypto::Hash> blockHashCheckpoints;

    if (hasMember(body, "blockHashCheckpoints"))
    {
        for (const auto &jsonHash : getArrayFromJSON(body, "blockHashCheckpoints"))
        {
            std::string hashStr = jsonHash.GetString();

            Crypto::Hash hash;
            Common::podFromHex(hashStr, hash);

            blockHashCheckpoints.push_back(hash);
        }
    }

    const uint64_t startHeight = hasMember(body, "startHeight")
        ? getUint64FromJSON(body, "startHeight")
        : 0;

    const uint64_t startTimestamp = hasMember(body, "startTimestamp")
        ? getUint64FromJSON(body, "startTimestamp")
        : 0;

    const uint64_t blockCount = hasMember(body, "blockCount")
        ? getUint64FromJSON(body, "blockCount")
        : 100;

    const bool skipCoinbaseTransactions = hasMember(body, "skipCoinbaseTransactions")
        ? getBoolFromJSON(body, "skipCoinbaseTransactions")
        : false;

    std::vector<WalletTypes::WalletBlockInfo> walletBlocks;
    std::optional<WalletTypes::TopBlock> topBlockInfo;

    const bool success = m_core->getWalletSyncData(
        blockHashCheckpoints,
        startHeight,
        startTimestamp,
        blockCount,
        skipCoinbaseTransactions,
        walletBlocks,
        topBlockInfo
    );

    if (!success)
    {
        return {SUCCESS, 500};
    }

    writer.Key("items");
    writer.StartArray();
    {
        for (const auto &block : walletBlocks)
        {
            writer.StartObject();

            if (block.coinbaseTransaction)
            {
                writer.Key("coinbaseTX");
                writer.StartObject();
                {
                    writer.Key("outputs");
                    writer.StartArray();
                    {
                        for (const auto &output : block.coinbaseTransaction->keyOutputs)
                        {
                            writer.StartObject();
                            {
                                writer.Key("key");
                                writer.String(Common::podToHex(output.key));

                                writer.Key("amount");
                                writer.Uint64(output.amount);
                            }
                            writer.EndObject();
                        }
                    }
                    writer.EndArray();

                    writer.Key("hash");
                    writer.String(Common::podToHex(block.coinbaseTransaction->hash));

                    writer.Key("txPublicKey");
                    writer.String(Common::podToHex(block.coinbaseTransaction->transactionPublicKey));

                    writer.Key("unlockTime");
                    writer.Uint64(block.coinbaseTransaction->unlockTime);
                }
                writer.EndObject();
            }

            writer.Key("transactions");
            writer.StartArray();
            {
                for (const auto &transaction : block.transactions)
                {
                    writer.StartObject();
                    {
                        writer.Key("outputs");
                        writer.StartArray();
                        {
                            for (const auto &output : transaction.keyOutputs)
                            {
                                writer.StartObject();
                                {
                                    writer.Key("key");
                                    writer.String(Common::podToHex(output.key));

                                    writer.Key("amount");
                                    writer.Uint64(output.amount);
                                }
                                writer.EndObject();
                            }
                        }
                        writer.EndArray();

                        writer.Key("hash");
                        writer.String(Common::podToHex(transaction.hash));

                        writer.Key("txPublicKey");
                        writer.String(Common::podToHex(transaction.transactionPublicKey));

                        writer.Key("unlockTime");
                        writer.Uint64(transaction.unlockTime);

                        writer.Key("paymentID");
                        writer.String(transaction.paymentID);

                        writer.Key("inputs");
                        writer.StartArray();
                        {
                            for (const auto &input : transaction.keyInputs)
                            {
                                writer.StartObject();
                                {
                                    writer.Key("amount");
                                    writer.Uint64(input.amount);

                                    writer.Key("key_offsets");
                                    writer.StartArray();
                                    {
                                        for (const auto &offset : input.outputIndexes)
                                        {
                                            writer.Uint64(offset);
                                        }
                                    }
                                    writer.EndArray();

                                    writer.Key("k_image");
                                    writer.String(Common::podToHex(input.keyImage));
                                }
                                writer.EndObject();
                            }
                        }
                        writer.EndArray();
                    }
                    writer.EndObject();
                }
            }
            writer.EndArray();

            writer.Key("blockHeight");
            writer.Uint64(block.blockHeight);

            writer.Key("blockHash");
            writer.String(Common::podToHex(block.blockHash));

            writer.Key("blockTimestamp");
            writer.Uint64(block.blockTimestamp);

            writer.EndObject();
        }
    }
    writer.EndArray();

    if (topBlockInfo)
    {
        writer.Key("topBlock");
        writer.StartObject();
        {
            writer.Key("hash");
            writer.String(Common::podToHex(topBlockInfo->hash));

            writer.Key("height");
            writer.Uint64(topBlockInfo->height);
        }
        writer.EndObject();
    }

    writer.Key("synced");
    writer.Bool(walletBlocks.empty());

    writer.Key("status");
    writer.String("OK");

    writer.EndObject();

    res.set_content(sb.GetString(), "application/json");

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::getGlobalIndexes(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    const uint64_t startHeight = getUint64FromJSON(body, "startHeight");
    const uint64_t endHeight = getUint64FromJSON(body, "endHeight");

    std::unordered_map<Crypto::Hash, std::vector<uint64_t>> indexes;

    const bool success = m_core->getGlobalIndexesForRange(startHeight, endHeight, indexes);

    writer.StartObject();

    if (!success)
    {
        writer.Key("status");
        writer.String("Failed");

        res.set_content(sb.GetString(), "application/json");

        return {SUCCESS, 500};
    }

    writer.Key("indexes");

    writer.StartArray();
    {
        for (const auto [hash, globalIndexes] : indexes)
        {
            writer.StartObject();

            writer.Key("key");
            writer.String(Common::podToHex(hash));
            
            writer.Key("value");
            writer.StartArray();
            {
                for (const auto index : globalIndexes)
                {
                    writer.Uint64(index);
                }
            }
            writer.EndArray();

            writer.EndObject();
        }
    }
    writer.EndArray();

    writer.Key("status");
    writer.String("OK");

    writer.EndObject();

    res.set_content(sb.GetString(), "application/json");

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::getBlockTemplate(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    const auto params = getObjectFromJSON(body, "params");

    writer.StartObject();

    const uint64_t reserveSize = getUint64FromJSON(params, "reserve_size");

    if (reserveSize > 255)
    {
        failJsonRpcRequest(
            -3,
            "Too big reserved size, maximum allowed is 255",
            res
        );

        return {SUCCESS, 200};
    }

    const std::string address = getStringFromJSON(params, "wallet_address");

    Error addressError = validateAddresses({address}, false);

    if (addressError)
    {
        failJsonRpcRequest(
            -4,
            addressError.getErrorMessage(),
            res
        );

        return {SUCCESS, 200};
    }

    const auto [publicSpendKey, publicViewKey] = Utilities::addressToKeys(address);

    CryptoNote::BlockTemplate blockTemplate;

    std::vector<uint8_t> blobReserve;
    blobReserve.resize(reserveSize, 0);

    uint64_t difficulty;
    uint32_t height;

    const auto [success, error] = m_core->getBlockTemplate(
        blockTemplate, publicViewKey, publicSpendKey, blobReserve, difficulty, height
    );

    if (!success)
    {
        failJsonRpcRequest(
            -5,
            "Failed to create block template: " + error,
            res
        );

        return {SUCCESS, 200};
    }

    std::vector<uint8_t> blockBlob = CryptoNote::toBinaryArray(blockTemplate);

    const auto transactionPublicKey = Utilities::getTransactionPublicKeyFromExtra(
        blockTemplate.baseTransaction.extra
    );

    uint64_t reservedOffset = 0;

    if (reserveSize > 0)
    {
        /* Find where in the block blob the transaction public key is */
        const auto it = std::search(
            blockBlob.begin(),
            blockBlob.end(),
            std::begin(transactionPublicKey.data),
            std::end(transactionPublicKey.data)
        );

        /* The reserved offset is past the transactionPublicKey, then past
         * the extra nonce tags */
        reservedOffset = (it - blockBlob.begin()) + sizeof(transactionPublicKey) + 3;

        if (reservedOffset + reserveSize > blockBlob.size())
        {
            failJsonRpcRequest(
                -5,
                "Internal error: failed to create block template, not enough space for reserved bytes",
                res
            );

            return {SUCCESS, 200};
        }
    }

    writer.Key("jsonrpc");
    writer.String("2.0");

    writer.Key("result");
    writer.StartObject();
    {
        writer.Key("height");
        writer.Uint(height);

        writer.Key("difficulty");
        writer.Uint64(difficulty);

        writer.Key("reserved_offset");
        writer.Uint64(reservedOffset);

        writer.Key("blocktemplate_blob");
        writer.String(Common::toHex(blockBlob));

        writer.Key("status");
        writer.String("OK");
    }
    writer.EndObject();

    writer.EndObject();

    res.set_content(sb.GetString(), "application/json");

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::submitBlock(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    const auto params = getArrayFromJSON(body, "params");

    if (params.Size() != 1)
    {
        failJsonRpcRequest(
            -1,
            "You must submit one and only one block blob! (Found " + std::to_string(params.Size()) + ")",
            res
        );

        return {SUCCESS, 200};
    }

    const std::string blockBlob = getStringFromJSONString(params[0]);

    std::vector<uint8_t> rawBlob;

    if (!Common::fromHex(blockBlob, rawBlob))
    {
        failJsonRpcRequest(
            -6,
            "Submitted block blob is not hex!",
            res
        );

        return {SUCCESS, 200};
    }

    const auto submitResult = m_core->submitBlock(rawBlob);

    if (submitResult != CryptoNote::error::AddBlockErrorCondition::BLOCK_ADDED)
    {
        failJsonRpcRequest(
            -7,
            "Block not accepted",
            res
        );

        return {SUCCESS, 200};
    }

    if (submitResult == CryptoNote::error::AddBlockErrorCode::ADDED_TO_MAIN
        || submitResult == CryptoNote::error::AddBlockErrorCode::ADDED_TO_ALTERNATIVE_AND_SWITCHED)
    {
        CryptoNote::NOTIFY_NEW_BLOCK::request newBlockMessage;

        CryptoNote::BlockTemplate blockTemplate;
        CryptoNote::fromBinaryArray(blockTemplate, rawBlob);
        newBlockMessage.block = CryptoNote::RawBlockLegacy(rawBlob, blockTemplate, m_core);
        newBlockMessage.hop = 0;
        newBlockMessage.current_blockchain_height = m_core->getTopBlockIndex() + 1;

        m_syncManager->relayBlock(newBlockMessage);
    }

    writer.StartObject();

    writer.Key("jsonrpc");
    writer.String("2.0");

    writer.Key("result");
    writer.StartObject();
    {
        writer.Key("status");
        writer.String("OK");
    }
    writer.EndObject();

    writer.EndObject();

    res.set_content(sb.GetString(), "application/json");

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::getBlockCount(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    writer.Key("jsonrpc");
    writer.String("2.0");

    writer.Key("result");
    writer.StartObject();
    {
        writer.Key("status");
        writer.String("OK");

        writer.Key("count");
        writer.Uint64(m_core->getTopBlockIndex() + 1);
    }
    writer.EndObject();

    writer.EndObject();

    res.set_content(sb.GetString(), "application/json");

    return {SUCCESS, 200};
}
