// settings.h - persist user-facing AppState options to a small ini file so they
// survive across runs (dock layout is persisted separately by ImGui).
#pragma once

struct AppState;

namespace KndSettings {
void Load(AppState& st, const char* path = "knetdbg_settings.ini");
void Save(const AppState& st, const char* path = "knetdbg_settings.ini");
}
