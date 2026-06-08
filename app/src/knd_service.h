// knd_service.h - load/unload the kernel driver via the Service Control Manager
// (the programmatic equivalent of `sc create` + `sc start` / `sc stop` + `sc delete`).
// Requires the app to run elevated, test-signing on, and a signed/test-signed .sys.
#pragma once

#include <string>

namespace KndService {

// Create (if needed) + start the kernel service "name" for the driver at sysPath.
// On failure, err receives a human-readable reason (incl. the Win32 error).
bool LoadDriver(const std::wstring& name, const std::wstring& sysPath, std::string& err);

// Stop + delete the service.
bool UnloadDriver(const std::wstring& name, std::string& err);

// Is the service currently running?
bool IsRunning(const std::wstring& name);

bool IsElevated();

} // namespace KndService
