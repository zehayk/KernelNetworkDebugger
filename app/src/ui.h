// ui.h - the ImGui presentation layer: theme, dockspace, and panels.
#pragma once

#include "app_model.h"
#include "knd_client.h"
#include "mitm_ca.h"
#include "mitm_proxy.h"
#include "tls_decrypt.h"
#include <cstdint>

#define KND_SERVICE_NAME_W L"knd"

struct AppState {
    // connection / capture
    bool     deviceConnected = false;
    bool     ringMapped      = false;
    bool     capturing       = false;
    char     status[256]     = "Disconnected — driver not opened";

    // selection / filtering
    uint64_t selectedFlow    = 0;
    char     filterText[128] = "";
    bool     showClosed      = true;
    int      inspectorDir    = 0;        // 0 = outbound, 1 = inbound

    // appearance / options
    float    accent[3]       = { 0.16f, 0.62f, 0.95f };
    float    fontScale       = 1.0f;
    bool     animations      = true;
    bool     multiViewport   = true;
    bool     mockData        = false;   // demo data when no driver is attached

    // MITM mode
    bool     mitmRunning     = false;
    int      proxyPort       = 8888;
    bool     useSystemProxy  = false;
    bool     wfpRedirect     = false;
    char     mitmStatus[256] = "MITM proxy: stopped";

    // driver service / CA
    char     sysPath[512]    = "knd.sys";          // path to the driver .sys
    char     driverStatus[200] = "driver: not checked";
    char     caStatus[200]   = "CA: not installed this session";

    // stealth SChannel key extraction (lsass)
    char     stealthStatus[256] = "SChannel key extractor: idle";

    // offline TLS decryption from a keylog
    char      keylogPath[512] = "C:\\ProgramData\\knd_sslkeys.log";
    bool      keylogLoaded = false;
    char      keylogStatus[128] = "keylog: not loaded";
    TlsKeyLog keylog;
    int      payloadCapMB    = 4;
    bool     autoScroll      = true;

    // packet log (Wireshark-style view)
    uint64_t selectedPacket  = 0;
    char     packetFilter[128] = "";

    // layout
    bool     layoutInitialized = false;
    bool     resetLayout       = false;
    bool     askResetLayout    = false;   // raises the confirmation modal

    // throughput history
    float    thru[120]       = {};   // records/sec
    float    thruB[120]      = {};   // bytes/sec
    int      thruHead        = 0;
    double   lastThruTs      = 0.0;
    uint64_t lastRecCount    = 0;
    uint64_t lastByteCount   = 0;
};

void Ui_ApplyTheme(const AppState& st);
void Ui_Frame(KndModel& model, KndClient& client, KndMitmCa& ca, KndMitmProxy& proxy, AppState& st);
