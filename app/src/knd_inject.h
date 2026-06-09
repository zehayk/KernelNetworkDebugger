// knd_inject.h - deliver knd_sslkeys.dll into a target process (lsass) and remove
// it cleanly. Usermode CreateRemoteThread+LoadLibrary path: works when the target
// is NOT a PPL. If lsass runs as a PPL (RunAsPPL=1) OpenProcess is denied and a
// kernel-assisted path is required instead.
#pragma once

#include <string>

namespace KndInject {

bool          EnableDebugPrivilege();
unsigned long FindProcessId(const wchar_t* exeName);   // returns PID or 0
std::wstring  DefaultDllPath();                          // <exe dir>\knd_sslkeys.dll

bool InjectDll(unsigned long pid, const wchar_t* dllPath, std::string& err);
bool UnhookDll(unsigned long pid, const wchar_t* dllPath, std::string& err);  // calls KndUnhook then frees

} // namespace KndInject
