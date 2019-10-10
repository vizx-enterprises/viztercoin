// Copyright (c) 2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

//////////////////////////
#include <rpc/RpcServer.h>
//////////////////////////

#include <iostream>

#include "version.h"

#include <logger/Logger.h>
#include <utilities/ColouredMsg.h>

RpcServer::RpcServer(
    const uint16_t bindPort,
    const std::string rpcBindIp,
    const std::string corsHeader,
    const std::string feeAddress,
    const uint64_t feeAmount,
    const RpcMode rpcMode,
    const std::shared_ptr<CryptoNote::Core> core,
    const std::shared_ptr<CryptoNote::NodeServer> p2p,
    const std::shared_ptr<CryptoNote::CryptoNoteProtocolHandler> syncManager):
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
    /* Route the request through our middleware function, before forwarding
       to the specified function */
    const auto router = [this](const auto function, const RpcMode routePermissions) {
        return [=](const httplib::Request &req, httplib::Response &res) {
            /* Pass the inputted function with the arguments passed through
               to middleware */
            middleware(
                req,
                res,
                routePermissions,
                std::bind(function, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3)
            );
        };
    };

    m_server.Get("/info", router(&RpcServer::info, RpcMode::Default))
            .Get("/fee", router(&RpcServer::fee, RpcMode::Default))
            .Get("/height", router(&RpcServer::height, RpcMode::Default))
            .Get("/peers", router(&RpcServer::peers, RpcMode::Default))

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

void RpcServer::middleware(
    const httplib::Request &req,
    httplib::Response &res,
    const RpcMode routePermissions,
    std::function<std::tuple<Error, uint16_t>(
        const httplib::Request &req,
        httplib::Response &res,
        const rapidjson::Document &body)> handler)
{
    rapidjson::Document jsonBody;

    Logger::logger.log(
        "Incoming " + req.method + " request: " + req.path,
        Logger::DEBUG,
        { Logger::DAEMON_RPC }
    );

    /* Not necessarily an error if a body isn't needed */
    if (jsonBody.Parse(req.body.c_str()).HasParseError())
    {
        if (!req.body.empty())
        {
            /* TODO: Set logger callback in daemon.cpp */
            Logger::logger.log(
                "Warning: received body is not JSON encoded!\n"
                "Key/value parameters are NOT supported.\n"
                "Body:\n" + req.body,
                Logger::INFO,
                { Logger::DAEMON_RPC }
            );
        }
    }

    if (m_corsHeader != "")
    {
        res.set_header("Access-Control-Allow-Origin", m_corsHeader);
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

        res.set_content(stream.str(), "text/plain");
        res.status = 403;

        return;
    }

    try
    {
        const auto [error, statusCode] = handler(req, res, jsonBody);

        if (error)
        {
            rapidjson::StringBuffer sb;
            rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

            writer.StartObject();

            writer.Key("errorCode");
            writer.Uint(error.getErrorCode());

            writer.Key("errorMessage");
            writer.String(error.getErrorMessage());

            res.set_content(sb.GetString(), "application/json");
            res.status = 400;
        }
        else
        {
            res.status = statusCode;
        }
    }
    catch (const std::invalid_argument &e)
    {
        Logger::logger.log(
            "Caught JSON exception, likely missing required json parameter: " + std::string(e.what()),
            Logger::FATAL,
            { Logger::DAEMON_RPC }
        );

        res.status = 400;
    }
    catch (const std::exception &e)
    {
        Logger::logger.log(
            "Caught unexpected exception: " + std::string(e.what()),
            Logger::FATAL,
            { Logger::DAEMON_RPC }
        );

        res.status = 500;
    }
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
    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::height(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::peers(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    return {SUCCESS, 200};
}
