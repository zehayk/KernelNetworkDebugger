// win_integration.cpp - see win_integration.h.
#include "win_integration.h"

#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>

#include <vector>
#include <cstdio>

namespace {

std::string ReadAll(const std::string& path)
{
    std::string out;
    FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "rb") != 0 || f == nullptr) { return out; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n > 0) { out.resize((size_t)n); out.resize(fread(out.data(), 1, (size_t)n, f)); }
    fclose(f);
    return out;
}

} // namespace

namespace KndWin {

bool InstallCaToRoot(const std::string& caPemPath, std::string& err)
{
    std::string pem = ReadAll(caPemPath);
    if (pem.empty()) { err = "CA PEM not found / empty: " + caPemPath; return false; }

    DWORD derLen = 0;
    if (!CryptStringToBinaryA(pem.c_str(), (DWORD)pem.size(), CRYPT_STRING_BASE64HEADER,
                              nullptr, &derLen, nullptr, nullptr)) {
        err = "CryptStringToBinary (size) failed"; return false;
    }
    std::vector<BYTE> der(derLen);
    if (!CryptStringToBinaryA(pem.c_str(), (DWORD)pem.size(), CRYPT_STRING_BASE64HEADER,
                              der.data(), &derLen, nullptr, nullptr)) {
        err = "CryptStringToBinary failed"; return false;
    }

    PCCERT_CONTEXT ctx = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                      der.data(), derLen);
    if (ctx == nullptr) { err = "CertCreateCertificateContext failed"; return false; }

    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
                                     CERT_SYSTEM_STORE_LOCAL_MACHINE, "ROOT");
    if (store == nullptr) {
        CertFreeCertificateContext(ctx);
        err = "open LOCAL_MACHINE\\ROOT failed (need elevation)"; return false;
    }

    bool ok = CertAddCertificateContextToStore(store, ctx, CERT_STORE_ADD_REPLACE_EXISTING, nullptr) != 0;
    if (!ok) { err = "CertAddCertificateContextToStore failed (err " + std::to_string(GetLastError()) + ")"; }

    CertCloseStore(store, 0);
    CertFreeCertificateContext(ctx);
    return ok;
}

bool SetSystemProxy(bool enable, const std::string& hostPort, std::string& err)
{
    HKEY key;
    LONG rc = RegOpenKeyExA(HKEY_CURRENT_USER,
                            "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                            0, KEY_SET_VALUE, &key);
    if (rc != ERROR_SUCCESS) { err = "open Internet Settings key failed"; return false; }

    DWORD en = enable ? 1u : 0u;
    RegSetValueExA(key, "ProxyEnable", 0, REG_DWORD, (const BYTE*)&en, sizeof(en));
    if (enable) {
        RegSetValueExA(key, "ProxyServer", 0, REG_SZ,
                       (const BYTE*)hostPort.c_str(), (DWORD)hostPort.size() + 1);
    }
    RegCloseKey(key);

    // tell WinINET to pick up the change immediately
    InternetSetOptionA(nullptr, INTERNET_OPTION_SETTINGS_CHANGED, nullptr, 0);
    InternetSetOptionA(nullptr, INTERNET_OPTION_REFRESH, nullptr, 0);
    (void)err;
    return true;
}

} // namespace KndWin
