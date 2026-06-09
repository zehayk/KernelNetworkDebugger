// tls_decrypt.h - offline TLS 1.2 (AES-GCM) record decryptor. Given the two captured
// ciphertext streams of a connection (from the driver) and a keylog mapping
// client_random -> master_secret (from the lsass hook or SSLKEYLOGFILE), it parses the
// handshake, derives the key block, and decrypts the application_data both directions.
//
// Scope: TLS 1.2 with AES-128/256-GCM (the common modern case). TLS 1.3 and CBC/ChaCha
// are detected and reported, not yet decrypted.
#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

class TlsKeyLog {
public:
    void   loadFile(const std::string& path);
    void   addLine(const std::string& line);
    size_t size() const { return map_.size(); }
    // master secret (48 bytes) for a client_random, or empty if unknown
    std::vector<uint8_t> masterSecret(const uint8_t clientRandom[32]) const;

private:
    std::unordered_map<std::string, std::vector<uint8_t>> map_;  // hex(client_random) -> secret
};

struct TlsDecryptResult {
    bool                 ok = false;
    std::string          note;
    uint16_t             cipherSuite = 0;
    bool                 isTls13 = false;
    std::vector<uint8_t> outPlain;   // client -> server application data
    std::vector<uint8_t> inPlain;    // server -> client application data
};

TlsDecryptResult TlsDecryptFlow(const std::vector<uint8_t>& outStream,
                                const std::vector<uint8_t>& inStream,
                                const TlsKeyLog& keylog);

// Self-contained round-trip test of the TLS1.2-GCM path (no external capture needed).
bool TlsDecryptSelfTest(std::string& detail);
