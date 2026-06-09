// app_model.h - turns raw ring records into a UI-friendly model of flows + payload.
// Single-threaded: the render loop polls the client then reads the model, same thread.
#pragma once

#include "knd_protocol.h"

#include <cstdint>
#include <string>
#include <vector>
#include <deque>
#include <unordered_map>

// One captured connection.
struct KndFlow {
    uint64_t flowId       = 0;
    uint64_t processId    = 0;
    uint8_t  protocol     = 0;     // KND_PROTO_*
    uint8_t  ipVersion    = 0;     // 4 / 6
    uint8_t  direction    = 0;     // KND_DIR_* at establishment
    uint16_t localPort    = 0;
    uint16_t remotePort   = 0;
    uint8_t  localAddr[16]{};
    uint8_t  remoteAddr[16]{};
    std::string processName;       // basename of the image path (UTF-8)
    std::string processPath;       // full image path (UTF-8)

    int64_t  firstTs      = 0;     // 100ns ticks
    int64_t  lastTs       = 0;
    uint64_t bytesOut     = 0;
    uint64_t bytesIn      = 0;
    uint64_t records      = 0;
    bool     closed       = false;

    // Captured payload, index 0 = outbound, 1 = inbound, each capped.
    std::vector<uint8_t> payload[2];
    bool     truncated[2] = { false, false };

    // UI: timestamp (ImGui time, seconds) when this flow was created / last got
    // data, used to drive the fade-in highlight without storing per-row state.
    double   uiCreated    = 0.0;
    double   uiActivity   = 0.0;
};

struct KndModelStats {
    uint64_t totalRecords = 0;
    uint64_t connOpens    = 0;
    uint64_t connCloses   = 0;
    uint64_t dataRecords  = 0;
    uint64_t payloadBytes = 0;
    uint64_t outBytes     = 0;
    uint64_t inBytes      = 0;
    uint64_t sizeHist[6]  = { 0, 0, 0, 0, 0, 0 };  // <128,<512,<1500,<4k,<16k,>=16k
};

// One entry in the chronological packet log (the Wireshark-style view).
struct KndPacket {
    uint64_t             no = 0;       // monotonic packet number
    int64_t              ts = 0;       // 100ns ticks
    uint64_t             flowId = 0;
    uint16_t             type = 0;     // KND_REC_*
    uint8_t              direction = 0;
    uint32_t             length = 0;   // payload length (KND_REC_DATA)
    std::string          info;         // human summary
    std::vector<uint8_t> preview;      // up to 64 payload bytes for the detail pane
};

class KndModel {
public:
    // Feed one record from KndClient::poll. 'now' is ImGui::GetTime() for UI timing.
    void ingest(const KND_RECORD* rec, double now);

    void clear();

    const std::vector<KndFlow>& flows() const { return flows_; }
    KndFlow* find(uint64_t flowId);

    const KndModelStats& stats() const { return stats_; }
    const std::deque<KndPacket>& packets() const { return packets_; }

    // Per-flow payload cap (bytes, each direction). Changing it only affects
    // future appends.
    size_t payloadCap = 4u * 1024u * 1024u;
    // Max packets retained in the chronological log (oldest dropped past this).
    size_t packetCap  = 50000;

private:
    KndFlow& getOrCreate(uint64_t flowId, double now);
    void     pushPacket(const KND_RECORD* rec, const KndFlow& f, uint8_t dir,
                        uint32_t len, const uint8_t* data);

    std::vector<KndFlow>                 flows_;
    std::unordered_map<uint64_t, size_t> index_;   // flowId -> flows_ index
    KndModelStats                        stats_;
    std::deque<KndPacket>                packets_;
    uint64_t                             packetNo_ = 0;
};

// ---- formatting helpers (shared with the UI) ----
std::string KndFormatAddr(const uint8_t addr[16], uint8_t ipVersion);
std::string KndFormatProto(uint8_t protocol);
std::string KndFormatTime(int64_t ticks100ns);     // local HH:MM:SS.mmm
std::string KndFormatBytes(uint64_t n);            // "12.3 KB"
