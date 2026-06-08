// mitm_ca.h - the MITM certificate authority: generate/persist a local root CA
// (private key NEVER leaves this machine), and mint+cache a per-host leaf cert
// (with SAN) signed by it. mbedTLS details are hidden behind a pimpl.
#pragma once

#include <string>
#include <mutex>
#include <unordered_map>

struct MintedCert {
    std::string certChainPem;   // leaf certificate + CA certificate (PEM)
    std::string keyPem;         // leaf private key (PEM)
};

class KndMitmCa {
public:
    KndMitmCa();
    ~KndMitmCa();
    KndMitmCa(const KndMitmCa&) = delete;
    KndMitmCa& operator=(const KndMitmCa&) = delete;

    // Load the CA from disk if both files exist, otherwise generate a new CA and
    // save it. The key file is created locally and must never be distributed.
    bool loadOrCreate(const std::string& caCertPath, const std::string& caKeyPath, std::string* err);

    bool ready() const { return ready_; }
    const std::string& caCertPem() const { return caCertPem_; }

    // Mint (or return cached) a leaf cert+key for a hostname (used as SAN/CN).
    bool certForHost(const std::string& host, MintedCert& out, std::string* err);

private:
    struct Impl;
    Impl*       d_ = nullptr;
    bool        ready_ = false;
    std::string caCertPem_;
    std::mutex  mtx_;
    std::unordered_map<std::string, MintedCert> cache_;
};
