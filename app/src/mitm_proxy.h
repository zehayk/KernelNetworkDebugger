// mitm_proxy.h - local TLS-terminating MITM proxy. Accepts explicit-proxy CONNECT,
// mints a per-host cert via KndMitmCa, terminates TLS toward the client, opens a TLS
// client connection to the real server, relays plaintext, and queues synthesized
// records (same wire format as the driver) for the UI thread to drain into KndModel.
#pragma once

#include "knd_protocol.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

class KndMitmCa;

class KndMitmProxy {
public:
    KndMitmProxy() = default;
    ~KndMitmProxy();
    KndMitmProxy(const KndMitmProxy&) = delete;
    KndMitmProxy& operator=(const KndMitmProxy&) = delete;

    bool start(uint16_t port, KndMitmCa* ca, std::string* err);
    void stop();
    bool running() const { return running_.load(); }
    uint16_t port() const { return port_; }
    uint64_t connections() const { return conns_.load(); }
    uint64_t active() const { return active_.load(); }

    // Called from the UI thread each frame to feed queued records into the model.
    void drain(const std::function<void(const KND_RECORD*)>& cb);

private:
    void listenLoop();
    void handleConn(intptr_t clientFd);
    void pushRecord(std::vector<uint8_t>&& rec);

    KndMitmCa*            ca_ = nullptr;
    uint16_t              port_ = 0;
    std::atomic<bool>     running_{ false };
    std::atomic<uint64_t> conns_{ 0 };
    std::atomic<uint64_t> active_{ 0 };
    std::atomic<uint64_t> nextFlow_{ 0 };
    intptr_t              listenFd_ = -1;
    std::thread           listener_;

    std::mutex                         qmtx_;
    std::vector<std::vector<uint8_t>>  queue_;

    std::mutex               tmtx_;
    std::vector<std::thread> conn_threads_;
};
