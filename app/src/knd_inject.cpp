// knd_inject.cpp - see knd_inject.h.
#include "knd_inject.h"

#include <windows.h>
#include <tlhelp32.h>

namespace {

std::string Win32Err(const char* what, DWORD e)
{
    return std::string(what) + " (err " + std::to_string(e) + ")";
}

HMODULE RemoteModuleBase(DWORD pid, const wchar_t* dllName)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) { return nullptr; }
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    HMODULE base = nullptr;
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, dllName) == 0) { base = me.hModule; break; }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return base;
}

const wchar_t* BaseName(const wchar_t* path)
{
    const wchar_t* s = wcsrchr(path, L'\\');
    return s ? s + 1 : path;
}

} // namespace

namespace KndInject {

bool EnableDebugPrivilege()
{
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) {
        return false;
    }
    LUID luid{};
    bool ok = false;
    if (LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ok = AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr) &&
             GetLastError() == ERROR_SUCCESS;
    }
    CloseHandle(tok);
    return ok;
}

unsigned long FindProcessId(const wchar_t* exeName)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) { return 0; }
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exeName) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

std::wstring DefaultDllPath()
{
    wchar_t exe[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring p(exe, n);
    size_t slash = p.find_last_of(L"\\/");
    std::wstring dir = (slash == std::wstring::npos) ? L"." : p.substr(0, slash);
    return dir + L"\\knd_sslkeys.dll";
}

bool InjectDll(unsigned long pid, const wchar_t* dllPath, std::string& err)
{
    if (pid == 0) { err = "target process not found"; return false; }
    if (GetFileAttributesW(dllPath) == INVALID_FILE_ATTRIBUTES) {
        err = "knd_sslkeys.dll not found next to the app"; return false;
    }
    EnableDebugPrivilege();

    HANDLE p = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                           PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (p == nullptr) {
        err = Win32Err("OpenProcess denied", GetLastError()) +
              " - if this is lsass it is likely PPL-protected (RunAsPPL=1); use the kernel path";
        return false;
    }

    bool ok = false;
    size_t bytes = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    void* remote = VirtualAllocEx(p, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remote != nullptr && WriteProcessMemory(p, remote, dllPath, bytes, nullptr)) {
        auto loadlib = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),
                                                              "LoadLibraryW");
        HANDLE t = CreateRemoteThread(p, nullptr, 0, loadlib, remote, 0, nullptr);
        if (t != nullptr) {
            WaitForSingleObject(t, 7000);
            DWORD ec = 0;
            GetExitCodeThread(t, &ec);     // low 32 bits of the loaded module base, 0 on failure
            CloseHandle(t);
            ok = (ec != 0);
            if (!ok) { err = "LoadLibrary in target returned NULL"; }
        } else {
            err = Win32Err("CreateRemoteThread failed", GetLastError());
        }
    } else {
        err = "VirtualAllocEx/WriteProcessMemory failed";
    }

    if (remote != nullptr) { VirtualFreeEx(p, remote, 0, MEM_RELEASE); }
    CloseHandle(p);
    return ok;
}

bool UnhookDll(unsigned long pid, const wchar_t* dllPath, std::string& err)
{
    const wchar_t* dllName = BaseName(dllPath);

    HMODULE remoteBase = RemoteModuleBase(pid, dllName);
    if (remoteBase == nullptr) { err = "DLL not loaded in target"; return false; }

    // Compute KndUnhook's RVA from the on-disk DLL, then call it in the target.
    HMODULE local = LoadLibraryExW(dllPath, nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (local == nullptr) { err = "cannot map DLL locally to resolve export"; return false; }
    FARPROC localProc = GetProcAddress(local, "KndUnhook");
    if (localProc == nullptr) { FreeLibrary(local); err = "KndUnhook export missing"; return false; }
    SIZE_T rva = (BYTE*)localProc - (BYTE*)local;
    FreeLibrary(local);

    HANDLE p = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                           PROCESS_VM_OPERATION | PROCESS_VM_READ, FALSE, pid);
    if (p == nullptr) { err = Win32Err("OpenProcess denied", GetLastError()); return false; }

    auto remoteProc = (LPTHREAD_START_ROUTINE)((BYTE*)remoteBase + rva);
    HANDLE t = CreateRemoteThread(p, nullptr, 0, remoteProc, nullptr, 0, nullptr);
    bool ok = false;
    if (t != nullptr) {
        WaitForSingleObject(t, 5000);
        CloseHandle(t);
        // free the module so a fresh build can be re-injected
        auto freelib = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),
                                                              "FreeLibrary");
        HANDLE t2 = CreateRemoteThread(p, nullptr, 0, freelib, remoteBase, 0, nullptr);
        if (t2 != nullptr) { WaitForSingleObject(t2, 5000); CloseHandle(t2); }
        ok = true;
    } else {
        err = Win32Err("CreateRemoteThread (unhook) failed", GetLastError());
    }
    CloseHandle(p);
    return ok;
}

} // namespace KndInject
