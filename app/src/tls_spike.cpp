// tls_spike.cpp - step-0 dependency + cert-minting spike (throwaway).
// Confirms mbedTLS links here AND that our CA-generation / leaf-minting flow works:
// gen CA key -> self-sign CA cert -> gen leaf key -> sign leaf with CA. This is the
// exact core of MITM mode, validated before building the whole subsystem on it.
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/x509_crt.h"

#include <cstdio>
#include <cstring>

static int GenRsaKey(mbedtls_pk_context* pk, mbedtls_ctr_drbg_context* rng)
{
    mbedtls_pk_init(pk);
    int rc = mbedtls_pk_setup(pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (rc != 0) { return rc; }
    return mbedtls_rsa_gen_key(mbedtls_pk_rsa(*pk), mbedtls_ctr_drbg_random, rng, 2048, 65537);
}

static int WriteCert(mbedtls_pk_context* subjKey, mbedtls_pk_context* issuerKey,
                     const char* subj, const char* issuer, int isCa,
                     const unsigned char* serial, size_t serialLen,
                     mbedtls_ctr_drbg_context* rng, unsigned char* outPem, size_t outSize)
{
    mbedtls_x509write_cert c;
    mbedtls_x509write_crt_init(&c);
    mbedtls_x509write_crt_set_subject_key(&c, subjKey);
    mbedtls_x509write_crt_set_issuer_key(&c, issuerKey);
    int rc = mbedtls_x509write_crt_set_subject_name(&c, subj);
    if (rc == 0) { rc = mbedtls_x509write_crt_set_issuer_name(&c, issuer); }
    mbedtls_x509write_crt_set_version(&c, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&c, MBEDTLS_MD_SHA256);
    if (rc == 0) { rc = mbedtls_x509write_crt_set_serial_raw(&c, (unsigned char*)serial, serialLen); }
    if (rc == 0) { rc = mbedtls_x509write_crt_set_validity(&c, "20240101000000", "20340101000000"); }
    if (rc == 0) { rc = mbedtls_x509write_crt_set_basic_constraints(&c, isCa, -1); }
    if (rc == 0) {
        rc = mbedtls_x509write_crt_pem(&c, outPem, outSize, mbedtls_ctr_drbg_random, rng);
    }
    mbedtls_x509write_crt_free(&c);
    return rc;
}

int main()
{
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context rng;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&rng);

    const char* pers = "knd-mitm-spike";
    int rc = mbedtls_ctr_drbg_seed(&rng, mbedtls_entropy_func, &entropy,
                                   (const unsigned char*)pers, strlen(pers));
    if (rc != 0) { printf("seed fail -0x%04x\n", -rc); return 1; }

    mbedtls_pk_context caKey, leafKey;
    if ((rc = GenRsaKey(&caKey, &rng)) != 0)   { printf("ca key fail -0x%04x\n", -rc); return 1; }
    if ((rc = GenRsaKey(&leafKey, &rng)) != 0) { printf("leaf key fail -0x%04x\n", -rc); return 1; }

    unsigned char pem[8192];
    const unsigned char caSerial[1] = { 1 };
    rc = WriteCert(&caKey, &caKey, "CN=knetdbg Root CA,O=knetdbg", "CN=knetdbg Root CA,O=knetdbg",
                   1, caSerial, sizeof(caSerial), &rng, pem, sizeof(pem));
    if (rc != 0) { printf("CA cert fail -0x%04x\n", -rc); return 1; }
    printf("CA cert PEM = %zu bytes\n", strlen((char*)pem));

    const unsigned char leafSerial[2] = { 0x10, 0x01 };
    rc = WriteCert(&leafKey, &caKey, "CN=example.com", "CN=knetdbg Root CA,O=knetdbg",
                   0, leafSerial, sizeof(leafSerial), &rng, pem, sizeof(pem));
    if (rc != 0) { printf("leaf cert fail -0x%04x\n", -rc); return 1; }
    printf("leaf cert PEM = %zu bytes\n", strlen((char*)pem));

    // Parse the leaf back to confirm it's a well-formed cert.
    mbedtls_x509_crt parsed;
    mbedtls_x509_crt_init(&parsed);
    rc = mbedtls_x509_crt_parse(&parsed, pem, strlen((char*)pem) + 1);
    printf("leaf re-parse rc=%d (0=ok)\n", rc);
    mbedtls_x509_crt_free(&parsed);

    mbedtls_pk_free(&caKey);
    mbedtls_pk_free(&leafKey);
    mbedtls_ctr_drbg_free(&rng);
    mbedtls_entropy_free(&entropy);
    printf("SPIKE OK\n");
    return 0;
}
