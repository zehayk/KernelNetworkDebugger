// settings.cpp - see settings.h.
#include "settings.h"
#include "ui.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>

namespace KndSettings {

void Save(const AppState& st, const char* path)
{
    FILE* f = nullptr;
    if (fopen_s(&f, path, "wb") != 0 || f == nullptr) { return; }
    fprintf(f, "accent=%f,%f,%f\n", st.accent[0], st.accent[1], st.accent[2]);
    fprintf(f, "fontScale=%f\n", st.fontScale);
    fprintf(f, "animations=%d\n", st.animations ? 1 : 0);
    fprintf(f, "multiViewport=%d\n", st.multiViewport ? 1 : 0);
    fprintf(f, "payloadCapMB=%d\n", st.payloadCapMB);
    fprintf(f, "autoScroll=%d\n", st.autoScroll ? 1 : 0);
    fprintf(f, "showClosed=%d\n", st.showClosed ? 1 : 0);
    fprintf(f, "proxyPort=%d\n", st.proxyPort);
    fprintf(f, "useSystemProxy=%d\n", st.useSystemProxy ? 1 : 0);
    fprintf(f, "sysPath=%s\n", st.sysPath);
    fclose(f);
}

void Load(AppState& st, const char* path)
{
    FILE* f = nullptr;
    if (fopen_s(&f, path, "rb") != 0 || f == nullptr) { return; }
    char line[1024];
    while (fgets(line, sizeof(line), f) != nullptr) {
        char* nl = strpbrk(line, "\r\n");
        if (nl != nullptr) { *nl = '\0'; }
        char* eq = strchr(line, '=');
        if (eq == nullptr) { continue; }
        *eq = '\0';
        const char* key = line;
        const char* val = eq + 1;

        if (strcmp(key, "accent") == 0) {
            sscanf_s(val, "%f,%f,%f", &st.accent[0], &st.accent[1], &st.accent[2]);
        } else if (strcmp(key, "fontScale") == 0) {
            st.fontScale = (float)atof(val);
        } else if (strcmp(key, "animations") == 0) {
            st.animations = atoi(val) != 0;
        } else if (strcmp(key, "multiViewport") == 0) {
            st.multiViewport = atoi(val) != 0;
        } else if (strcmp(key, "payloadCapMB") == 0) {
            st.payloadCapMB = atoi(val);
        } else if (strcmp(key, "autoScroll") == 0) {
            st.autoScroll = atoi(val) != 0;
        } else if (strcmp(key, "showClosed") == 0) {
            st.showClosed = atoi(val) != 0;
        } else if (strcmp(key, "proxyPort") == 0) {
            st.proxyPort = atoi(val);
        } else if (strcmp(key, "useSystemProxy") == 0) {
            st.useSystemProxy = atoi(val) != 0;
        } else if (strcmp(key, "sysPath") == 0) {
            strncpy_s(st.sysPath, sizeof(st.sysPath), val, _TRUNCATE);
        }
    }
    fclose(f);
}

} // namespace KndSettings
