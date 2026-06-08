// win_integration.h - Windows integration for MITM mode: install the CA into the
// machine Root store, and set/clear the system (WinINET) proxy. Both are deliberate,
// user-gated, VM-only actions (installing a MITM root CA is a real trust change).
#pragma once

#include <string>

namespace KndWin {

// Add the PEM CA at caPemPath to LOCAL_MACHINE\ROOT (needs elevation).
bool InstallCaToRoot(const std::string& caPemPath, std::string& err);

// Enable/disable the WinINET system proxy pointing at hostPort (e.g. "127.0.0.1:8888").
bool SetSystemProxy(bool enable, const std::string& hostPort, std::string& err);

} // namespace KndWin
