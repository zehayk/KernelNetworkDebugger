// knd_sslkeys.cpp -> knd_sslkeys.dll
//
// Injected into lsass.exe to extract SChannel TLS session secrets *without* a hook
// in the analyzed app's own process (SChannel derives all its keys in lsass). It
// hooks ncryptsslp!SslGenerateMasterKey (TLS 1.2) via MinHook and writes
// SSLKEYLOGFILE lines that Wireshark / our offline decryptor can consume.
//
// SAFETY (this runs inside lsass — an access violation here bugchecks the box):
//  - every read of the key object / parameter buffers is wrapped in __try/__except;
//  - the master-secret OFFSET is not trusted blind: the first few captures dump the
//    bytes around the key object to a calibration log so the offset can be confirmed
//    for the specific Windows build before relying on the CLIENT_RANDOM output;
//  - KndUnhook() (exported) removes the hooks cleanly so a bad build is reversible
//    without a reboot (call it from a remote thread before FreeLibrary).
//
// VM ONLY. Never load on the host. TLS 1.3 (SslExpandTrafficKeys) + the other
// ncrypt entry points are added after 1.2 is calibrated.

#include <windows.h>
#include <ncrypt.h>
#include "MinHook.h"

#include <cstdio>
#include <cstring>

#ifndef NCRYPTBUFFER_SSL_CLIENT_RANDOM
#define NCRYPTBUFFER_SSL_CLIENT_RANDOM 20
#endif
#ifndef NCRYPTBUFFER_SSL_SERVER_RANDOM
#define NCRYPTBUFFER_SSL_SERVER_RANDOM 21
#endif

static const char* KEYLOG = "C:\\ProgramData\\knd_sslkeys.log";
static const char* CALIB  = "C:\\ProgramData\\knd_sslkeys_calib.log";
static const char* DBG    = "C:\\ProgramData\\knd_sslkeys_dbg.log";

static CRITICAL_SECTION g_cs;
static volatile LONG     g_calib = 0;

static void Append(const char* path, const char* text)
{
    EnterCriticalSection(&g_cs);
    HANDLE h = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD wr = 0;
        SetFilePointer(h, 0, nullptr, FILE_END);
        WriteFile(h, text, (DWORD)strlen(text), &wr, nullptr);
        CloseHandle(h);
    }
    LeaveCriticalSection(&g_cs);
}

static void Hex(const BYTE* p, DWORD n, char* out)
{
    static const char* H = "0123456789abcdef";
    for (DWORD i = 0; i < n; ++i) { out[i * 2] = H[p[i] >> 4]; out[i * 2 + 1] = H[p[i] & 0xF]; }
    out[n * 2] = '\0';
}

// ncryptsslp!SslGenerateMasterKey
typedef SECURITY_STATUS (WINAPI *SslGenerateMasterKey_t)(
    NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_KEY_HANDLE*,
    DWORD, DWORD, NCryptBufferDesc*, PBYTE, DWORD, DWORD*, DWORD);

static SslGenerateMasterKey_t g_origGenMaster = nullptr;

static void CaptureMasterKey(NCRYPT_KEY_HANDLE hKey, NCryptBufferDesc* params)
{
    const BYTE* clientRand = nullptr;
    DWORD       clientLen = 0;

    if (params != nullptr) {
        for (ULONG i = 0; i < params->cBuffers; ++i) {
            NCryptBuffer* b = &params->pBuffers[i];
            if (b->BufferType == NCRYPTBUFFER_SSL_CLIENT_RANDOM) {
                clientRand = (const BYTE*)b->pvBuffer;
                clientLen = b->cbBuffer;
            }
        }
    }

    const BYTE* key = (const BYTE*)hKey;

    // One-time calibration: dump the key object so the real master-secret offset can
    // be confirmed for this Windows build instead of trusting a blog's magic number.
    if (InterlockedIncrement(&g_calib) <= 3) {
        char hexbuf[300], dump[420];
        DWORD magic = *(const DWORD*)(key + 4);
        Hex(key, 0x80, hexbuf);
        _snprintf_s(dump, sizeof(dump), _TRUNCATE,
                    "[calib] magic@+4=0x%08x first0x80=%s\n", magic, hexbuf);
        Append(CALIB, dump);
        if (clientRand != nullptr && clientLen > 0) {
            char cr[80];
            Hex(clientRand, clientLen > 32 ? 32 : clientLen, cr);
            char cb[160];
            _snprintf_s(cb, sizeof(cb), _TRUNCATE, "[calib] client_random=%s\n", cr);
            Append(CALIB, cb);
        }
    }

    // Documented TLS 1.2 layout: 48-byte master secret at key+0x1c (VERIFY via the
    // calibration log for your build before trusting these lines).
    const BYTE* secret = key + 0x1c;
    if (clientRand != nullptr && clientLen >= 32) {
        char rc[80], sc[120], line[256];
        Hex(clientRand, 32, rc);
        Hex(secret, 48, sc);
        _snprintf_s(line, sizeof(line), _TRUNCATE, "CLIENT_RANDOM %s %s\n", rc, sc);
        Append(KEYLOG, line);
    }
}

static SECURITY_STATUS WINAPI Hook_SslGenerateMasterKey(
    NCRYPT_PROV_HANDLE hProv, NCRYPT_KEY_HANDLE hPriv, NCRYPT_KEY_HANDLE hPub,
    NCRYPT_KEY_HANDLE* phMaster, DWORD dwProtocol, DWORD dwCipherSuite,
    NCryptBufferDesc* pParams, PBYTE pbOut, DWORD cbOut, DWORD* pcbResult, DWORD dwFlags)
{
    SECURITY_STATUS rc = g_origGenMaster(hProv, hPriv, hPub, phMaster, dwProtocol,
                                         dwCipherSuite, pParams, pbOut, cbOut, pcbResult, dwFlags);
    if (rc == 0 && phMaster != nullptr && *phMaster != 0) {
        __try {
            CaptureMasterKey(*phMaster, pParams);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Append(DBG, "[knd] exception during key capture (offset wrong? sehed)\n");
        }
    }
    return rc;
}

static DWORD WINAPI InstallThread(LPVOID)
{
    if (MH_Initialize() != MH_OK) { Append(DBG, "[knd] MH_Initialize failed\n"); return 0; }

    // ncrypt.dll exports the SChannel SSL key functions by name (SslGenerateMasterKey,
    // SslExpandTrafficKeys, ...); ncryptsslp.dll exports none of them by name.
    HMODULE m = GetModuleHandleW(L"ncrypt.dll");
    if (m == nullptr) { m = LoadLibraryW(L"ncrypt.dll"); }
    if (m == nullptr) { Append(DBG, "[knd] ncrypt.dll not present\n"); return 0; }

    void* target = (void*)GetProcAddress(m, "SslGenerateMasterKey");
    if (target == nullptr) { Append(DBG, "[knd] SslGenerateMasterKey not found\n"); return 0; }

    if (MH_CreateHook(target, &Hook_SslGenerateMasterKey, (void**)&g_origGenMaster) != MH_OK ||
        MH_EnableHook(target) != MH_OK) {
        Append(DBG, "[knd] hook install failed\n");
        return 0;
    }
    Append(DBG, "[knd] SslGenerateMasterKey hooked - capturing TLS1.2 master secrets\n");
    return 0;
}

// Clean removal: call from a remote thread BEFORE FreeLibrary (avoids doing MinHook
// work under the loader lock in DLL_PROCESS_DETACH).
extern "C" __declspec(dllexport) DWORD WINAPI KndUnhook(LPVOID)
{
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    Append(DBG, "[knd] unhooked\n");
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInst);
        InitializeCriticalSection(&g_cs);
        // Install off the loader lock.
        HANDLE t = CreateThread(nullptr, 0, InstallThread, nullptr, 0, nullptr);
        if (t != nullptr) { CloseHandle(t); }
    }
    return TRUE;
}
