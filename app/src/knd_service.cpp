// knd_service.cpp - see knd_service.h.
#include "knd_service.h"

#include <windows.h>
#include <string>

namespace {

std::string Win32Msg(const char* what, DWORD e)
{
    char* msg = nullptr;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                       FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, e, 0, (LPSTR)&msg, 0, nullptr);
    std::string s = std::string(what) + " (err " + std::to_string(e) + ": " +
                    (msg ? msg : "?") + ")";
    if (msg) { LocalFree(msg); }
    // trim trailing CRLF from the system message
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ')) { s.pop_back(); }
    return s;
}

} // namespace

namespace KndService {

bool IsElevated()
{
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) { return false; }
    TOKEN_ELEVATION el{};
    DWORD cb = 0;
    bool ok = GetTokenInformation(tok, TokenElevation, &el, sizeof(el), &cb) && el.TokenIsElevated;
    CloseHandle(tok);
    return ok;
}

bool LoadDriver(const std::wstring& name, const std::wstring& sysPath, std::string& err)
{
    if (!IsElevated()) { err = "must run elevated (Administrator) to load a driver"; return false; }

    if (GetFileAttributesW(sysPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        err = "driver .sys not found at the configured path"; return false;
    }

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (scm == nullptr) { err = Win32Msg("OpenSCManager", GetLastError()); return false; }

    SC_HANDLE svc = CreateServiceW(scm, name.c_str(), name.c_str(), SERVICE_ALL_ACCESS,
                                   SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                                   sysPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    if (svc == nullptr) {
        DWORD e = GetLastError();
        if (e == ERROR_SERVICE_EXISTS) {
            svc = OpenServiceW(scm, name.c_str(), SERVICE_ALL_ACCESS);
        }
        if (svc == nullptr) {
            err = Win32Msg("CreateService", e);
            CloseServiceHandle(scm);
            return false;
        }
    }

    bool ok = true;
    if (!StartServiceW(svc, 0, nullptr)) {
        DWORD e = GetLastError();
        if (e != ERROR_SERVICE_ALREADY_RUNNING) {
            err = Win32Msg("StartService", e);
            ok = false;
        }
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

bool UnloadDriver(const std::wstring& name, std::string& err)
{
    if (!IsElevated()) { err = "must run elevated to unload a driver"; return false; }

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (scm == nullptr) { err = Win32Msg("OpenSCManager", GetLastError()); return false; }
    SC_HANDLE svc = OpenServiceW(scm, name.c_str(), SERVICE_ALL_ACCESS);
    if (svc == nullptr) { err = Win32Msg("OpenService", GetLastError()); CloseServiceHandle(scm); return false; }

    SERVICE_STATUS st{};
    ControlService(svc, SERVICE_CONTROL_STOP, &st);   // best-effort stop
    bool ok = DeleteService(svc) != 0;
    if (!ok) { err = Win32Msg("DeleteService", GetLastError()); }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

bool IsRunning(const std::wstring& name)
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm == nullptr) { return false; }
    SC_HANDLE svc = OpenServiceW(scm, name.c_str(), SERVICE_QUERY_STATUS);
    bool running = false;
    if (svc != nullptr) {
        SERVICE_STATUS st{};
        if (QueryServiceStatus(svc, &st)) { running = (st.dwCurrentState == SERVICE_RUNNING); }
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return running;
}

} // namespace KndService
