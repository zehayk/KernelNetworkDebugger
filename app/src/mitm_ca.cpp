// mitm_ca.cpp - see mitm_ca.h.
#include "mitm_ca.h"

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"

#include <cstdio>
#include <cstring>
#include <atomic>

static const char* kCaDn = "CN=knetdbg Root CA,O=knetdbg,OU=MITM";

struct KndMitmCa::Impl {
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context rng;
    mbedtls_pk_context       caKey;
    std::atomic<uint64_t>    serial{ 0x1000 };
};

static std::string ReadFile(const std::string& path)
{
    std::string out;
    FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "rb") != 0 || f == nullptr) { return out; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n > 0) {
        out.resize((size_t)n);
        size_t rd = fread(out.data(), 1, (size_t)n, f);
        out.resize(rd);
    }
    fclose(f);
    return out;
}

static bool WriteFile(const std::string& path, const std::string& data)
{
    FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "wb") != 0 || f == nullptr) { return false; }
    size_t wr = fwrite(data.data(), 1, data.size(), f);
    fclose(f);
    return wr == data.size();
}

static bool GenRsaKey(mbedtls_pk_context* pk, mbedtls_ctr_drbg_context* rng)
{
    mbedtls_pk_init(pk);
    if (mbedtls_pk_setup(pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0) { return false; }
    return mbedtls_rsa_gen_key(mbedtls_pk_rsa(*pk), mbedtls_ctr_drbg_random, rng, 2048, 65537) == 0;
}

KndMitmCa::KndMitmCa() : d_(new Impl)
{
    mbedtls_entropy_init(&d_->entropy);
    mbedtls_ctr_drbg_init(&d_->rng);
    mbedtls_pk_init(&d_->caKey);
}

KndMitmCa::~KndMitmCa()
{
    if (d_ != nullptr) {
        mbedtls_pk_free(&d_->caKey);
        mbedtls_ctr_drbg_free(&d_->rng);
        mbedtls_entropy_free(&d_->entropy);
        delete d_;
    }
}

bool KndMitmCa::loadOrCreate(const std::string& caCertPath, const std::string& caKeyPath, std::string* err)
{
    const char* pers = "knd-mitm-ca";
    if (mbedtls_ctr_drbg_seed(&d_->rng, mbedtls_entropy_func, &d_->entropy,
                              (const unsigned char*)pers, strlen(pers)) != 0) {
        if (err) { *err = "RNG seed failed"; }
        return false;
    }

    std::string certPem = ReadFile(caCertPath);
    std::string keyPem  = ReadFile(caKeyPath);

    if (!certPem.empty() && !keyPem.empty()) {
        // load existing CA key
        if (mbedtls_pk_parse_key(&d_->caKey, (const unsigned char*)keyPem.c_str(), keyPem.size() + 1,
                                 nullptr, 0, mbedtls_ctr_drbg_random, &d_->rng) == 0) {
            caCertPem_ = certPem;
            ready_ = true;
            return true;
        }
        // fall through to regenerate if the key didn't parse
    }

    // generate a fresh CA
    if (!GenRsaKey(&d_->caKey, &d_->rng)) {
        if (err) { *err = "CA key generation failed"; }
        return false;
    }

    mbedtls_x509write_cert c;
    mbedtls_x509write_crt_init(&c);
    mbedtls_x509write_crt_set_subject_key(&c, &d_->caKey);
    mbedtls_x509write_crt_set_issuer_key(&c, &d_->caKey);
    int rc = mbedtls_x509write_crt_set_subject_name(&c, kCaDn);
    if (rc == 0) { rc = mbedtls_x509write_crt_set_issuer_name(&c, kCaDn); }
    mbedtls_x509write_crt_set_version(&c, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&c, MBEDTLS_MD_SHA256);
    const unsigned char serial[] = { 0x01 };
    if (rc == 0) { rc = mbedtls_x509write_crt_set_serial_raw(&c, (unsigned char*)serial, sizeof(serial)); }
    if (rc == 0) { rc = mbedtls_x509write_crt_set_validity(&c, "20240101000000", "20340101000000"); }
    if (rc == 0) { rc = mbedtls_x509write_crt_set_basic_constraints(&c, 1, 0); }

    unsigned char buf[8192];
    if (rc == 0) { rc = mbedtls_x509write_crt_pem(&c, buf, sizeof(buf), mbedtls_ctr_drbg_random, &d_->rng); }
    if (rc != 0) {
        mbedtls_x509write_crt_free(&c);
        if (err) { *err = "CA cert creation failed"; }
        return false;
    }
    caCertPem_.assign((char*)buf);
    mbedtls_x509write_crt_free(&c);

    // export CA private key to PEM and persist both
    unsigned char keybuf[8192];
    if (mbedtls_pk_write_key_pem(&d_->caKey, keybuf, sizeof(keybuf)) != 0) {
        if (err) { *err = "CA key export failed"; }
        return false;
    }
    std::string caKeyPemOut((char*)keybuf);

    if (!WriteFile(caCertPath, caCertPem_) || !WriteFile(caKeyPath, caKeyPemOut)) {
        if (err) { *err = "failed to persist CA files"; }
        return false;
    }

    ready_ = true;
    return true;
}

bool KndMitmCa::certForHost(const std::string& host, MintedCert& out, std::string* err)
{
    if (!ready_) { if (err) { *err = "CA not ready"; } return false; }

    std::lock_guard<std::mutex> lk(mtx_);
    auto it = cache_.find(host);
    if (it != cache_.end()) { out = it->second; return true; }

    mbedtls_pk_context leafKey;
    if (!GenRsaKey(&leafKey, &d_->rng)) { if (err) { *err = "leaf key gen failed"; } return false; }

    mbedtls_x509write_cert c;
    mbedtls_x509write_crt_init(&c);
    mbedtls_x509write_crt_set_subject_key(&c, &leafKey);
    mbedtls_x509write_crt_set_issuer_key(&c, &d_->caKey);

    std::string subj = "CN=" + host;
    int rc = mbedtls_x509write_crt_set_subject_name(&c, subj.c_str());
    if (rc == 0) { rc = mbedtls_x509write_crt_set_issuer_name(&c, kCaDn); }
    mbedtls_x509write_crt_set_version(&c, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&c, MBEDTLS_MD_SHA256);

    uint64_t s = d_->serial.fetch_add(1);
    unsigned char serial[8];
    for (int i = 0; i < 8; ++i) { serial[i] = (unsigned char)(s >> (8 * (7 - i))); }
    if (rc == 0) { rc = mbedtls_x509write_crt_set_serial_raw(&c, serial, sizeof(serial)); }
    if (rc == 0) { rc = mbedtls_x509write_crt_set_validity(&c, "20240101000000", "20340101000000"); }
    if (rc == 0) { rc = mbedtls_x509write_crt_set_basic_constraints(&c, 0, -1); }

    // Subject Alternative Name = DNS:host (modern clients require SAN, ignore CN).
    mbedtls_x509_san_list san;
    memset(&san, 0, sizeof(san));
    san.node.type = MBEDTLS_X509_SAN_DNS_NAME;
    san.node.san.unstructured_name.tag = MBEDTLS_ASN1_IA5_STRING;
    san.node.san.unstructured_name.p = (unsigned char*)host.c_str();
    san.node.san.unstructured_name.len = host.size();
    san.next = nullptr;
    if (rc == 0) { rc = mbedtls_x509write_crt_set_subject_alternative_name(&c, &san); }

    unsigned char certbuf[8192];
    if (rc == 0) { rc = mbedtls_x509write_crt_pem(&c, certbuf, sizeof(certbuf), mbedtls_ctr_drbg_random, &d_->rng); }
    if (rc != 0) {
        mbedtls_x509write_crt_free(&c);
        mbedtls_pk_free(&leafKey);
        if (err) { *err = "leaf cert creation failed"; }
        return false;
    }

    unsigned char keybuf[8192];
    int krc = mbedtls_pk_write_key_pem(&leafKey, keybuf, sizeof(keybuf));
    mbedtls_x509write_crt_free(&c);
    mbedtls_pk_free(&leafKey);
    if (krc != 0) { if (err) { *err = "leaf key export failed"; } return false; }

    MintedCert mc;
    mc.certChainPem.assign((char*)certbuf);
    mc.certChainPem += caCertPem_;          // append CA so the chain is complete
    mc.keyPem.assign((char*)keybuf);

    cache_[host] = mc;
    out = mc;
    return true;
}
