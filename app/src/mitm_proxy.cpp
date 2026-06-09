// mitm_proxy.cpp - see mitm_proxy.h.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>     // SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT

#include "mitm_proxy.h"
#include "mitm_ca.h"

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"

#include <cstring>
#include <string>

// ------------------------------------------------------------------ records

static int64_t NowTicks()
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    return (static_cast<int64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
}

static std::vector<uint8_t> BuildConnOpen(uint64_t flow, const std::string& host, uint16_t port)
{
    std::vector<uint8_t> buf(sizeof(KND_RECORD) + sizeof(KND_CONN_PAYLOAD), 0);
    auto* r = reinterpret_cast<KND_RECORD*>(buf.data());
    r->length = static_cast<ULONG>(buf.size());
    r->type = KND_REC_CONN_OPEN;
    r->timestamp = NowTicks();
    auto* p = reinterpret_cast<KND_CONN_PAYLOAD*>(buf.data() + sizeof(KND_RECORD));
    p->flowId = flow;
    p->processId = 0;
    p->protocol = KND_PROTO_TCP;
    p->ipVersion = KND_IPV4;
    p->direction = KND_DIR_OUTBOUND;
    p->remotePort = port;

    std::string label = host + " (MITM)";
    int n = MultiByteToWideChar(CP_UTF8, 0, label.c_str(), -1, p->processPath, KND_PROCPATH_CHARS);
    if (n > 0) { p->processPathChars = static_cast<USHORT>(n - 1); }
    return buf;
}

static std::vector<uint8_t> BuildData(uint64_t flow, uint8_t dir, const uint8_t* data, uint32_t len)
{
    std::vector<uint8_t> buf(sizeof(KND_RECORD) + sizeof(KND_DATA_PAYLOAD) + len);
    auto* r = reinterpret_cast<KND_RECORD*>(buf.data());
    r->length = static_cast<ULONG>(buf.size());
    r->type = KND_REC_DATA;
    r->flags = 0;
    r->timestamp = NowTicks();
    auto* p = reinterpret_cast<KND_DATA_PAYLOAD*>(buf.data() + sizeof(KND_RECORD));
    p->flowId = flow;
    p->direction = dir;
    p->dataKind = KND_DATA_PLAINTEXT;
    p->dataLength = len;
    memcpy(buf.data() + sizeof(KND_RECORD) + sizeof(KND_DATA_PAYLOAD), data, len);
    return buf;
}

static std::vector<uint8_t> BuildConnClose(uint64_t flow)
{
    std::vector<uint8_t> buf(sizeof(KND_RECORD) + sizeof(KND_CONN_PAYLOAD), 0);
    auto* r = reinterpret_cast<KND_RECORD*>(buf.data());
    r->length = static_cast<ULONG>(buf.size());
    r->type = KND_REC_CONN_CLOSE;
    r->timestamp = NowTicks();
    auto* p = reinterpret_cast<KND_CONN_PAYLOAD*>(buf.data() + sizeof(KND_RECORD));
    p->flowId = flow;
    return buf;
}

// ------------------------------------------------------------------ helpers

// Read the explicit-proxy request preamble (until CRLFCRLF) from a raw socket.
static bool ReadPreamble(SOCKET s, std::string& out)
{
    char c;
    out.clear();
    while (out.size() < 8192) {
        int n = recv(s, &c, 1, 0);
        if (n <= 0) { return false; }
        out.push_back(c);
        if (out.size() >= 4 && out.compare(out.size() - 4, 4, "\r\n\r\n") == 0) { return true; }
    }
    return false;
}

// Parse "CONNECT host:port HTTP/1.1" -> host, port.
static bool ParseConnect(const std::string& pre, std::string& host, uint16_t& port)
{
    if (pre.compare(0, 8, "CONNECT ") != 0) { return false; }
    size_t sp = pre.find(' ', 8);
    if (sp == std::string::npos) { return false; }
    std::string hp = pre.substr(8, sp - 8);
    size_t colon = hp.rfind(':');
    if (colon == std::string::npos) { host = hp; port = 443; return true; }
    host = hp.substr(0, colon);
    port = static_cast<uint16_t>(atoi(hp.c_str() + colon + 1));
    if (port == 0) { port = 443; }
    return true;
}

// Recover the original destination of a WFP-redirected (transparent) connection.
static bool QueryOriginalDest(SOCKET s, KND_REDIRECT_CTX& out)
{
    BYTE buf[256];
    DWORD bytes = 0;
    if (WSAIoctl(s, SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT, nullptr, 0,
                 buf, sizeof(buf), &bytes, nullptr, nullptr) != 0) {
        return false;
    }
    if (bytes < sizeof(KND_REDIRECT_CTX)) { return false; }
    memcpy(&out, buf, sizeof(out));
    return true;
}

// Pull the SNI host_name from a peeked TLS ClientHello (returns "" if absent).
static std::string ParseSni(const unsigned char* d, size_t n)
{
    if (n < 43 || d[0] != 0x16) { return ""; }
    size_t p = 5;                                   // record header
    if (p + 4 > n || d[p] != 0x01) { return ""; }   // handshake = ClientHello
    p += 4 + 2 + 32;                                // hs header + version + random
    if (p >= n) { return ""; }
    p += 1 + d[p];                                  // session id
    if (p + 2 > n) { return ""; }
    p += 2 + ((d[p] << 8) | d[p + 1]);              // cipher suites
    if (p >= n) { return ""; }
    p += 1 + d[p];                                  // compression methods
    if (p + 2 > n) { return ""; }
    size_t extEnd = p + 2 + ((d[p] << 8) | d[p + 1]);
    p += 2;
    if (extEnd > n) { extEnd = n; }
    while (p + 4 <= extEnd) {
        uint16_t et = (uint16_t)((d[p] << 8) | d[p + 1]);
        uint16_t el = (uint16_t)((d[p + 2] << 8) | d[p + 3]);
        p += 4;
        if (et == 0) {  // server_name: list_len(2) type(1) name_len(2) name
            if (p + 5 <= extEnd) {
                uint16_t nameLen = (uint16_t)((d[p + 3] << 8) | d[p + 4]);
                if (p + 5 + nameLen <= extEnd) { return std::string((const char*)d + p + 5, nameLen); }
            }
            return "";
        }
        p += el;
    }
    return "";
}

// ------------------------------------------------------------------ proxy

KndMitmProxy::~KndMitmProxy()
{
    stop();
}

bool KndMitmProxy::start(uint16_t port, KndMitmCa* ca, std::string* err)
{
    if (running_.load()) { return true; }
    if (ca == nullptr || !ca->ready()) { if (err) { *err = "CA not ready"; } return false; }
    ca_ = ca;

    mbedtls_net_context* lc = new mbedtls_net_context;
    mbedtls_net_init(lc);
    char portStr[8];
    _snprintf_s(portStr, sizeof(portStr), _TRUNCATE, "%u", port);
    int rc = mbedtls_net_bind(lc, "127.0.0.1", portStr, MBEDTLS_NET_PROTO_TCP);
    if (rc != 0) {
        mbedtls_net_free(lc);
        delete lc;
        if (err) { *err = "bind failed on 127.0.0.1:" + std::string(portStr); }
        return false;
    }
    listenFd_ = static_cast<intptr_t>(lc->fd);
    delete lc; // we keep the fd; mbedtls_net_context was only for binding

    port_ = port;
    running_.store(true);
    listener_ = std::thread([this] { listenLoop(); });
    return true;
}

void KndMitmProxy::stop()
{
    if (!running_.exchange(false)) { return; }
    if (listenFd_ != -1) {
        closesocket(static_cast<SOCKET>(listenFd_));
        listenFd_ = -1;
    }
    if (listener_.joinable()) { listener_.join(); }
    std::vector<std::thread> threads;
    {
        std::lock_guard<std::mutex> lk(tmtx_);
        threads.swap(conn_threads_);
    }
    for (auto& t : threads) { if (t.joinable()) { t.join(); } }
}

void KndMitmProxy::pushRecord(std::vector<uint8_t>&& rec)
{
    std::lock_guard<std::mutex> lk(qmtx_);
    queue_.push_back(std::move(rec));
}

void KndMitmProxy::drain(const std::function<void(const KND_RECORD*)>& cb)
{
    std::vector<std::vector<uint8_t>> local;
    {
        std::lock_guard<std::mutex> lk(qmtx_);
        local.swap(queue_);
    }
    for (auto& r : local) {
        cb(reinterpret_cast<const KND_RECORD*>(r.data()));
    }
}

void KndMitmProxy::listenLoop()
{
    SOCKET ls = static_cast<SOCKET>(listenFd_);
    while (running_.load()) {
        fd_set rd;
        FD_ZERO(&rd);
        FD_SET(ls, &rd);
        timeval tv{ 0, 200000 };
        int sel = select(0, &rd, nullptr, nullptr, &tv);
        if (!running_.load()) { break; }
        if (sel <= 0) { continue; }

        SOCKET cs = accept(ls, nullptr, nullptr);
        if (cs == INVALID_SOCKET) { continue; }

        conns_.fetch_add(1);
        std::lock_guard<std::mutex> lk(tmtx_);
        // prune finished threads opportunistically
        conn_threads_.emplace_back([this, cs] { handleConn(static_cast<intptr_t>(cs)); });
    }
}

void KndMitmProxy::handleConn(intptr_t clientFdIn)
{
    SOCKET clientSock = static_cast<SOCKET>(clientFdIn);
    active_.fetch_add(1);
    uint64_t flow = (1ull << 63) | nextFlow_.fetch_add(1);

    // mbedTLS state
    mbedtls_entropy_context entropy;  mbedtls_ctr_drbg_context rng;
    mbedtls_entropy_init(&entropy);   mbedtls_ctr_drbg_init(&rng);
    const char* pers = "knd-mitm-conn";
    mbedtls_ctr_drbg_seed(&rng, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers));

    mbedtls_net_context clientNet; clientNet.fd = static_cast<int>(clientSock);
    mbedtls_net_context upstreamNet; mbedtls_net_init(&upstreamNet);
    mbedtls_ssl_context cssl, ssl_up; mbedtls_ssl_init(&cssl); mbedtls_ssl_init(&ssl_up);
    mbedtls_ssl_config cconf, upconf; mbedtls_ssl_config_init(&cconf); mbedtls_ssl_config_init(&upconf);
    mbedtls_x509_crt leafChain; mbedtls_pk_context leafKey;
    mbedtls_x509_crt_init(&leafChain); mbedtls_pk_init(&leafKey);

    bool opened = false;
    std::string host;       // upstream connect target (CONNECT host or original IP)
    std::string certHost;   // hostname the minted cert is issued for
    uint16_t port = 443;

    do {
        char first = 0;
        if (recv(clientSock, &first, 1, MSG_PEEK) != 1) { break; }
        if ((unsigned char)first == 0x16) {
            // Transparent WFP-redirected TLS connection: no CONNECT preamble.
            // Take the cert host from SNI and the real destination from the driver.
            unsigned char peek[2048];
            int pn = recv(clientSock, (char*)peek, sizeof(peek), MSG_PEEK);
            if (pn <= 0) { break; }
            certHost = ParseSni(peek, (size_t)pn);
            KND_REDIRECT_CTX rc;
            if (!QueryOriginalDest(clientSock, rc)) { break; }
            char ip[64];
            _snprintf_s(ip, sizeof(ip), _TRUNCATE, "%u.%u.%u.%u",
                        rc.origAddr[0], rc.origAddr[1], rc.origAddr[2], rc.origAddr[3]);
            host = ip;
            port = rc.origPort;
            if (certHost.empty()) { certHost = host; }
        } else {
            // Explicit-proxy connection: "CONNECT host:port".
            std::string pre;
            if (!ReadPreamble(clientSock, pre)) { break; }
            if (!ParseConnect(pre, host, port)) {
                const char* resp = "HTTP/1.1 501 Not Implemented\r\n\r\n";
                send(clientSock, resp, (int)strlen(resp), 0);
                break;
            }
            const char* ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
            send(clientSock, ok, (int)strlen(ok), 0);
            certHost = host;
        }

        // mint cert for the target host
        MintedCert mc; std::string e;
        if (!ca_->certForHost(certHost, mc, &e)) { break; }
        if (mbedtls_x509_crt_parse(&leafChain, (const unsigned char*)mc.certChainPem.c_str(),
                                   mc.certChainPem.size() + 1) != 0) { break; }
        if (mbedtls_pk_parse_key(&leafKey, (const unsigned char*)mc.keyPem.c_str(), mc.keyPem.size() + 1,
                                 nullptr, 0, mbedtls_ctr_drbg_random, &rng) != 0) { break; }

        // server side toward the client
        if (mbedtls_ssl_config_defaults(&cconf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
                                        MBEDTLS_SSL_PRESET_DEFAULT) != 0) { break; }
        mbedtls_ssl_conf_rng(&cconf, mbedtls_ctr_drbg_random, &rng);
        if (mbedtls_ssl_conf_own_cert(&cconf, &leafChain, &leafKey) != 0) { break; }
        if (mbedtls_ssl_setup(&cssl, &cconf) != 0) { break; }
        mbedtls_ssl_set_bio(&cssl, &clientNet, mbedtls_net_send, mbedtls_net_recv, nullptr);

        int hs;
        while ((hs = mbedtls_ssl_handshake(&cssl)) != 0) {
            if (hs != MBEDTLS_ERR_SSL_WANT_READ && hs != MBEDTLS_ERR_SSL_WANT_WRITE) { break; }
        }
        if (hs != 0) { break; }

        // client side toward the real server
        char portStr[8];
        _snprintf_s(portStr, sizeof(portStr), _TRUNCATE, "%u", port);
        if (mbedtls_net_connect(&upstreamNet, host.c_str(), portStr, MBEDTLS_NET_PROTO_TCP) != 0) { break; }
        if (mbedtls_ssl_config_defaults(&upconf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                        MBEDTLS_SSL_PRESET_DEFAULT) != 0) { break; }
        mbedtls_ssl_conf_authmode(&upconf, MBEDTLS_SSL_VERIFY_NONE); // debugging proxy: never block
        mbedtls_ssl_conf_rng(&upconf, mbedtls_ctr_drbg_random, &rng);
        if (mbedtls_ssl_setup(&ssl_up, &upconf) != 0) { break; }
        mbedtls_ssl_set_hostname(&ssl_up, certHost.c_str());
        mbedtls_ssl_set_bio(&ssl_up, &upstreamNet, mbedtls_net_send, mbedtls_net_recv, nullptr);
        while ((hs = mbedtls_ssl_handshake(&ssl_up)) != 0) {
            if (hs != MBEDTLS_ERR_SSL_WANT_READ && hs != MBEDTLS_ERR_SSL_WANT_WRITE) { break; }
        }
        if (hs != 0) { break; }

        pushRecord(BuildConnOpen(flow, certHost, port));
        opened = true;

        // non-blocking relay
        mbedtls_net_set_nonblock(&clientNet);
        mbedtls_net_set_nonblock(&upstreamNet);
        SOCKET cfd = static_cast<SOCKET>(clientNet.fd);
        SOCKET ufd = static_cast<SOCKET>(upstreamNet.fd);
        unsigned char buf[16384];
        bool done = false;
        while (!done && running_.load()) {
            fd_set rd; FD_ZERO(&rd); FD_SET(cfd, &rd); FD_SET(ufd, &rd);
            timeval tv{ 0, 200000 };
            select(0, &rd, nullptr, nullptr, &tv);

            // client -> server (outbound plaintext)
            for (;;) {
                int n = mbedtls_ssl_read(&cssl, buf, sizeof(buf));
                if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) { break; }
                if (n <= 0) { done = true; break; }
                pushRecord(BuildData(flow, KND_DIR_OUTBOUND, buf, (uint32_t)n));
                int off = 0;
                while (off < n) {
                    int w = mbedtls_ssl_write(&ssl_up, buf + off, n - off);
                    if (w == MBEDTLS_ERR_SSL_WANT_READ || w == MBEDTLS_ERR_SSL_WANT_WRITE) { continue; }
                    if (w <= 0) { done = true; break; }
                    off += w;
                }
            }
            if (done) { break; }

            // server -> client (inbound plaintext)
            for (;;) {
                int n = mbedtls_ssl_read(&ssl_up, buf, sizeof(buf));
                if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) { break; }
                if (n <= 0) { done = true; break; }
                pushRecord(BuildData(flow, KND_DIR_INBOUND, buf, (uint32_t)n));
                int off = 0;
                while (off < n) {
                    int w = mbedtls_ssl_write(&cssl, buf + off, n - off);
                    if (w == MBEDTLS_ERR_SSL_WANT_READ || w == MBEDTLS_ERR_SSL_WANT_WRITE) { continue; }
                    if (w <= 0) { done = true; break; }
                    off += w;
                }
            }
        }
    } while (false);

    if (opened) { pushRecord(BuildConnClose(flow)); }

    mbedtls_ssl_close_notify(&cssl);
    mbedtls_ssl_close_notify(&ssl_up);
    mbedtls_ssl_free(&cssl); mbedtls_ssl_free(&ssl_up);
    mbedtls_ssl_config_free(&cconf); mbedtls_ssl_config_free(&upconf);
    mbedtls_x509_crt_free(&leafChain); mbedtls_pk_free(&leafKey);
    mbedtls_net_free(&upstreamNet);
    closesocket(clientSock);
    mbedtls_ctr_drbg_free(&rng); mbedtls_entropy_free(&entropy);
    active_.fetch_sub(1);
}
