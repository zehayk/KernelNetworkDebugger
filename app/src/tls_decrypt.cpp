// tls_decrypt.cpp - see tls_decrypt.h.
#include "tls_decrypt.h"

#include "mbedtls/md.h"
#include "mbedtls/gcm.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>

// ---------------------------------------------------------------- hex

static std::string BytesToHex(const uint8_t* p, size_t n)
{
    static const char* H = "0123456789abcdef";
    std::string s;
    s.resize(n * 2);
    for (size_t i = 0; i < n; ++i) { s[i * 2] = H[p[i] >> 4]; s[i * 2 + 1] = H[p[i] & 0xF]; }
    return s;
}

static std::vector<uint8_t> HexToBytes(const std::string& h)
{
    std::vector<uint8_t> out;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') { return c - '0'; }
        if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
        if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
        return -1;
    };
    for (size_t i = 0; i + 1 < h.size(); i += 2) {
        int hi = nib(h[i]), lo = nib(h[i + 1]);
        if (hi < 0 || lo < 0) { break; }
        out.push_back((uint8_t)((hi << 4) | lo));
    }
    return out;
}

// ---------------------------------------------------------------- keylog

void TlsKeyLog::addLine(const std::string& line)
{
    // "CLIENT_RANDOM <hex client_random> <hex master_secret>"
    if (line.compare(0, 14, "CLIENT_RANDOM ") != 0) { return; }
    size_t a = 14;
    size_t b = line.find(' ', a);
    if (b == std::string::npos) { return; }
    std::string cr = line.substr(a, b - a);
    std::string ms = line.substr(b + 1);
    while (!ms.empty() && (ms.back() == '\r' || ms.back() == '\n' || ms.back() == ' ')) { ms.pop_back(); }
    if (cr.size() != 64) { return; }
    std::string key = cr;
    for (auto& c : key) { if (c >= 'A' && c <= 'F') { c = (char)(c - 'A' + 'a'); } }
    map_[key] = HexToBytes(ms);
}

void TlsKeyLog::loadFile(const std::string& path)
{
    FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "rb") != 0 || f == nullptr) { return; }
    char line[1024];
    while (fgets(line, sizeof(line), f) != nullptr) { addLine(line); }
    fclose(f);
}

std::vector<uint8_t> TlsKeyLog::masterSecret(const uint8_t clientRandom[32]) const
{
    auto it = map_.find(BytesToHex(clientRandom, 32));
    return (it == map_.end()) ? std::vector<uint8_t>() : it->second;
}

// ---------------------------------------------------------------- PRF

static std::vector<uint8_t> Phash(const uint8_t* secret, size_t slen,
                                  const uint8_t* seed, size_t seedLen,
                                  size_t outLen, mbedtls_md_type_t md)
{
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(md);
    size_t hlen = mbedtls_md_get_size(info);
    std::vector<uint8_t> out, a(seed, seed + seedLen), aN(hlen);

    mbedtls_md_hmac(info, secret, slen, a.data(), a.size(), aN.data());  // A(1)
    a = aN;
    while (out.size() < outLen) {
        std::vector<uint8_t> in(a);
        in.insert(in.end(), seed, seed + seedLen);
        std::vector<uint8_t> blk(hlen);
        mbedtls_md_hmac(info, secret, slen, in.data(), in.size(), blk.data());
        out.insert(out.end(), blk.begin(), blk.end());
        mbedtls_md_hmac(info, secret, slen, a.data(), a.size(), aN.data());  // A(i+1)
        a = aN;
    }
    out.resize(outLen);
    return out;
}

static std::vector<uint8_t> Prf12(const std::vector<uint8_t>& secret, const char* label,
                                  const uint8_t* seed, size_t seedLen, size_t outLen,
                                  mbedtls_md_type_t md)
{
    std::vector<uint8_t> ls(label, label + strlen(label));
    ls.insert(ls.end(), seed, seed + seedLen);
    return Phash(secret.data(), secret.size(), ls.data(), ls.size(), outLen, md);
}

// ---------------------------------------------------------------- suites

struct SuiteInfo { uint8_t keyLen; mbedtls_md_type_t prf; bool gcm; bool tls13; };

static bool LookupSuite(uint16_t cs, SuiteInfo& si)
{
    switch (cs) {
    case 0xC02F: case 0xC02B: case 0x009C: si = { 16, MBEDTLS_MD_SHA256, true,  false }; return true;
    case 0xC030: case 0xC02C: case 0x009D: si = { 32, MBEDTLS_MD_SHA384, true,  false }; return true;
    case 0x1301: si = { 16, MBEDTLS_MD_SHA256, true,  true }; return true; // TLS1.3
    case 0x1302: si = { 32, MBEDTLS_MD_SHA384, true,  true }; return true;
    case 0x1303: si = { 32, MBEDTLS_MD_SHA256, false, true }; return true; // chacha
    default: return false;
    }
}

struct DirKeys { std::vector<uint8_t> cKey, sKey, cIV, sIV; };

static DirKeys DeriveKeyBlock(const std::vector<uint8_t>& master, const uint8_t cr[32],
                              const uint8_t sr[32], const SuiteInfo& si)
{
    uint8_t seed[64];
    memcpy(seed, sr, 32);
    memcpy(seed + 32, cr, 32);
    std::vector<uint8_t> kb = Prf12(master, "key expansion", seed, 64,
                                    (size_t)2 * si.keyLen + 8, si.prf);
    DirKeys k;
    size_t o = 0;
    k.cKey.assign(kb.begin() + o, kb.begin() + o + si.keyLen); o += si.keyLen;
    k.sKey.assign(kb.begin() + o, kb.begin() + o + si.keyLen); o += si.keyLen;
    k.cIV.assign(kb.begin() + o, kb.begin() + o + 4);          o += 4;
    k.sIV.assign(kb.begin() + o, kb.begin() + o + 4);          o += 4;
    return k;
}

// ---------------------------------------------------------------- records

struct Record { uint8_t type; uint16_t ver; const uint8_t* payload; size_t len; };

static std::vector<Record> ParseRecords(const std::vector<uint8_t>& s)
{
    std::vector<Record> recs;
    size_t i = 0;
    while (i + 5 <= s.size()) {
        uint8_t type = s[i];
        uint16_t ver = (uint16_t)((s[i + 1] << 8) | s[i + 2]);
        uint16_t len = (uint16_t)((s[i + 3] << 8) | s[i + 4]);
        if (i + 5 + len > s.size()) { break; }
        recs.push_back({ type, ver, s.data() + i + 5, len });
        i += 5 + len;
    }
    return recs;
}

static bool FindHandshake(const std::vector<Record>& recs, uint8_t wantType,
                          const uint8_t** body, uint32_t* blen)
{
    for (const auto& r : recs) {
        if (r.type != 22) { continue; }
        size_t i = 0;
        while (i + 4 <= r.len) {
            uint8_t ht = r.payload[i];
            uint32_t hl = (uint32_t)((r.payload[i + 1] << 16) | (r.payload[i + 2] << 8) | r.payload[i + 3]);
            if (i + 4 + hl > r.len) { break; }
            if (ht == wantType) { *body = r.payload + i + 4; *blen = hl; return true; }
            i += 4 + hl;
        }
    }
    return false;
}

static bool GcmDecryptRecord(mbedtls_gcm_context* gcm, const std::vector<uint8_t>& iv4,
                             uint64_t seq, const Record& r, std::vector<uint8_t>& out)
{
    if (r.len < 8 + 16) { return false; }
    const uint8_t* explicitN = r.payload;
    const uint8_t* ct = r.payload + 8;
    size_t ctLen = r.len - 8 - 16;
    const uint8_t* tag = r.payload + r.len - 16;

    uint8_t nonce[12];
    memcpy(nonce, iv4.data(), 4);
    memcpy(nonce + 4, explicitN, 8);

    uint8_t aad[13];
    for (int i = 0; i < 8; ++i) { aad[i] = (uint8_t)(seq >> (56 - 8 * i)); }
    aad[8] = r.type;
    aad[9] = (uint8_t)(r.ver >> 8);
    aad[10] = (uint8_t)(r.ver & 0xFF);
    aad[11] = (uint8_t)(ctLen >> 8);
    aad[12] = (uint8_t)(ctLen & 0xFF);

    out.resize(ctLen);
    return mbedtls_gcm_auth_decrypt(gcm, ctLen, nonce, 12, aad, 13, tag, 16, ct, out.data()) == 0;
}

static void DecryptDir(const std::vector<Record>& recs, const std::vector<uint8_t>& key,
                       const std::vector<uint8_t>& iv4, std::vector<uint8_t>& out)
{
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key.data(), (unsigned)(key.size() * 8)) != 0) {
        mbedtls_gcm_free(&gcm);
        return;
    }
    bool enc = false;
    uint64_t seq = 0;
    for (const auto& r : recs) {
        if (!enc) { if (r.type == 20) { enc = true; } continue; }  // ChangeCipherSpec
        std::vector<uint8_t> pt;
        if (!GcmDecryptRecord(&gcm, iv4, seq, r, pt)) { break; }
        ++seq;
        if (r.type == 23) { out.insert(out.end(), pt.begin(), pt.end()); }
    }
    mbedtls_gcm_free(&gcm);
}

// ---------------------------------------------------------------- public

TlsDecryptResult TlsDecryptFlow(const std::vector<uint8_t>& outStream,
                                const std::vector<uint8_t>& inStream,
                                const TlsKeyLog& keylog)
{
    TlsDecryptResult r;
    auto outRecs = ParseRecords(outStream);
    auto inRecs = ParseRecords(inStream);

    const uint8_t* chBody; uint32_t chLen;
    const uint8_t* shBody; uint32_t shLen;
    if (!FindHandshake(outRecs, 1, &chBody, &chLen) || chLen < 34) {
        r.note = "no ClientHello (client_random) in the outbound stream"; return r;
    }
    if (!FindHandshake(inRecs, 2, &shBody, &shLen) || shLen < 35) {
        r.note = "no ServerHello in the inbound stream"; return r;
    }
    uint8_t cr[32], sr[32];
    memcpy(cr, chBody + 2, 32);
    memcpy(sr, shBody + 2, 32);
    uint8_t sidLen = shBody[2 + 32];
    size_t off = 2 + 32 + 1 + sidLen;
    if (off + 2 > shLen) { r.note = "malformed ServerHello"; return r; }
    uint16_t suite = (uint16_t)((shBody[off] << 8) | shBody[off + 1]);
    r.cipherSuite = suite;

    SuiteInfo si;
    if (!LookupSuite(suite, si)) {
        char b[64]; std::snprintf(b, sizeof(b), "unsupported cipher suite 0x%04x", suite);
        r.note = b; return r;
    }
    if (si.tls13) { r.isTls13 = true; r.note = "TLS 1.3 capture (decryptor handles TLS 1.2 GCM so far)"; return r; }
    if (!si.gcm)  { r.note = "non-GCM cipher not supported yet"; return r; }

    std::vector<uint8_t> master = keylog.masterSecret(cr);
    if (master.size() != 48) {
        r.note = "no master secret for this client_random in the keylog"; return r;
    }

    DirKeys k = DeriveKeyBlock(master, cr, sr, si);
    DecryptDir(outRecs, k.cKey, k.cIV, r.outPlain);
    DecryptDir(inRecs, k.sKey, k.sIV, r.inPlain);
    r.ok = true;
    return r;
}

// ---------------------------------------------------------------- self-test

static void PutRec(std::vector<uint8_t>& s, uint8_t type, const uint8_t* p, size_t n)
{
    s.push_back(type); s.push_back(0x03); s.push_back(0x03);
    s.push_back((uint8_t)(n >> 8)); s.push_back((uint8_t)(n & 0xFF));
    s.insert(s.end(), p, p + n);
}

bool TlsDecryptSelfTest(std::string& detail)
{
    SuiteInfo si{ 16, MBEDTLS_MD_SHA256, true, false };
    uint16_t suite = 0xC02F;

    std::vector<uint8_t> master(48);
    uint8_t cr[32], sr[32];
    for (int i = 0; i < 48; ++i) { master[i] = (uint8_t)(i + 1); }
    for (int i = 0; i < 32; ++i) { cr[i] = (uint8_t)(0x40 + i); sr[i] = (uint8_t)(0x80 + i); }

    DirKeys k = DeriveKeyBlock(master, cr, sr, si);

    const char* msg = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    size_t plen = strlen(msg);

    // encrypt one client application_data record at seq 0
    uint8_t explicitN[8] = { 0, 0, 0, 0, 0, 0, 0, 1 };
    uint8_t nonce[12]; memcpy(nonce, k.cIV.data(), 4); memcpy(nonce + 4, explicitN, 8);
    uint8_t aad[13] = { 0,0,0,0,0,0,0,0, 23, 0x03, 0x03, (uint8_t)(plen >> 8), (uint8_t)(plen & 0xFF) };
    std::vector<uint8_t> ct(plen), tag(16);
    mbedtls_gcm_context gcm; mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, k.cKey.data(), (unsigned)(k.cKey.size() * 8));
    mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plen, nonce, 12, aad, 13,
                              (const uint8_t*)msg, ct.data(), 16, tag.data());
    mbedtls_gcm_free(&gcm);

    std::vector<uint8_t> appRec;            // explicit nonce + ciphertext + tag
    appRec.insert(appRec.end(), explicitN, explicitN + 8);
    appRec.insert(appRec.end(), ct.begin(), ct.end());
    appRec.insert(appRec.end(), tag.begin(), tag.end());

    // minimal ClientHello / ServerHello handshake bodies
    std::vector<uint8_t> ch = { 0x01, 0x00, 0x00, 0x29, 0x03, 0x03 };
    ch.insert(ch.end(), cr, cr + 32);
    ch.insert(ch.end(), { 0x00, 0x00, 0x02, 0xC0, 0x2F, 0x01, 0x00 });
    std::vector<uint8_t> sh = { 0x02, 0x00, 0x00, 0x26, 0x03, 0x03 };
    sh.insert(sh.end(), sr, sr + 32);
    sh.insert(sh.end(), { 0x00, (uint8_t)(suite >> 8), (uint8_t)(suite & 0xFF), 0x00 });
    uint8_t ccs[1] = { 0x01 };

    std::vector<uint8_t> outStream, inStream;
    PutRec(outStream, 22, ch.data(), ch.size());
    PutRec(outStream, 20, ccs, 1);
    PutRec(outStream, 23, appRec.data(), appRec.size());
    PutRec(inStream, 22, sh.data(), sh.size());
    PutRec(inStream, 20, ccs, 1);

    TlsKeyLog keylog;
    keylog.addLine("CLIENT_RANDOM " + BytesToHex(cr, 32) + " " + BytesToHex(master.data(), 48));

    TlsDecryptResult r = TlsDecryptFlow(outStream, inStream, keylog);
    if (!r.ok) { detail = "decrypt failed: " + r.note; return false; }
    std::string got((const char*)r.outPlain.data(), r.outPlain.size());
    if (got != msg) { detail = "plaintext mismatch: '" + got + "'"; return false; }
    detail = "round-trip OK (" + std::to_string(plen) + " bytes via AES-128-GCM)";
    return true;
}
