#include "tls_decrypt.h"
#include <cstdio>

int main()
{
    std::string detail;
    bool ok = TlsDecryptSelfTest(detail);
    std::printf("%s: %s\n", ok ? "PASS" : "FAIL", detail.c_str());
    return ok ? 0 : 1;
}
