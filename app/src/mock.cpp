// mock.cpp - see mock.h. Builds records in the exact wire format and feeds them
// through KndModel::ingest, i.e. the same parse path the real ring uses.
#include "mock.h"

#include <windows.h>
#include <vector>
#include <cstring>
#include <cstdlib>

static double                 s_lastConn = 0.0;
static double                 s_lastData = 0.0;
static uint64_t               s_seq      = 1;
static uint64_t               s_nextFlow = 1000;
static std::vector<uint64_t>  s_flows;

static int64_t NowTicks()
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    return (static_cast<int64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
}

static void EmitConnOpen(KndModel& m, double now, uint64_t flow,
                         const char* proc, const uint8_t rip[4], uint16_t rport)
{
    uint8_t buf[sizeof(KND_RECORD) + sizeof(KND_CONN_PAYLOAD)];
    memset(buf, 0, sizeof(buf));

    auto* r = reinterpret_cast<KND_RECORD*>(buf);
    r->length    = sizeof(buf);
    r->type      = KND_REC_CONN_OPEN;
    r->sequence  = s_seq++;
    r->timestamp = NowTicks();

    auto* p = reinterpret_cast<KND_CONN_PAYLOAD*>(buf + sizeof(KND_RECORD));
    p->flowId     = flow;
    p->processId  = 4000 + (flow % 1000);
    p->protocol   = KND_PROTO_TCP;
    p->ipVersion  = KND_IPV4;
    p->direction  = KND_DIR_OUTBOUND;
    p->localPort  = static_cast<uint16_t>(50000 + (flow % 10000));
    p->remotePort = rport;
    const uint8_t lip[4] = { 192, 168, 1, 50 };
    memcpy(p->localAddr, lip, 4);
    memcpy(p->remoteAddr, rip, 4);

    wchar_t wpath[KND_PROCPATH_CHARS];
    int n = MultiByteToWideChar(CP_UTF8, 0, proc, -1, wpath, KND_PROCPATH_CHARS);
    if (n > 0) {
        n -= 1; // drop the null
        memcpy(p->processPath, wpath, static_cast<size_t>(n) * sizeof(wchar_t));
        p->processPathChars = static_cast<USHORT>(n);
    }

    m.ingest(r, now);
}

static void EmitData(KndModel& m, double now, uint64_t flow, uint8_t dir,
                     const void* data, uint32_t len)
{
    std::vector<uint8_t> buf(sizeof(KND_RECORD) + sizeof(KND_DATA_PAYLOAD) + len);

    auto* r = reinterpret_cast<KND_RECORD*>(buf.data());
    r->length    = static_cast<ULONG>(buf.size());
    r->type      = KND_REC_DATA;
    r->sequence  = s_seq++;
    r->timestamp = NowTicks();

    auto* p = reinterpret_cast<KND_DATA_PAYLOAD*>(buf.data() + sizeof(KND_RECORD));
    p->flowId     = flow;
    p->direction  = dir;
    p->dataKind   = KND_DATA_CIPHERTEXT;
    p->dataLength = len;
    memcpy(buf.data() + sizeof(KND_RECORD) + sizeof(KND_DATA_PAYLOAD), data, len);

    m.ingest(r, now);
}

void Mock_Pump(KndModel& model, double now)
{
    static bool seeded = false;
    if (!seeded) { srand(1234); seeded = true; }

    if (now - s_lastConn > 0.8 && s_flows.size() < 14) {
        s_lastConn = now;
        uint64_t flow = s_nextFlow++;
        const char* procs[] = {
            "C:\\Windows\\System32\\svchost.exe", "C:\\Program Files\\Google\\Chrome\\chrome.exe",
            "C:\\samples\\malware_sample.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "C:\\Users\\analyst\\AppData\\Local\\Discord\\Discord.exe", "C:\\Windows\\System32\\curl.exe"
        };
        const char* proc = procs[rand() % 6];
        uint8_t rip[4] = { static_cast<uint8_t>(20 + rand() % 200), static_cast<uint8_t>(rand() % 255),
                           static_cast<uint8_t>(rand() % 255), static_cast<uint8_t>(1 + rand() % 254) };
        EmitConnOpen(model, now, flow, proc, rip, (rand() % 2) ? 443 : 80);
        s_flows.push_back(flow);
    }

    if (!s_flows.empty() && now - s_lastData > 0.12) {
        s_lastData = now;
        uint64_t flow = s_flows[rand() % s_flows.size()];
        if (rand() % 2) {
            static const char* req =
                "GET /api/v1/telemetry?id=42 HTTP/1.1\r\n"
                "Host: cdn.example.net\r\n"
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                "Accept: */*\r\n\r\n";
            EmitData(model, now, flow, KND_DIR_OUTBOUND, req, static_cast<uint32_t>(strlen(req)));
        } else {
            static const char* resp =
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: 27\r\n\r\n"
                "{\"ok\":true,\"value\":1234567}\r\n";
            EmitData(model, now, flow, KND_DIR_INBOUND, resp, static_cast<uint32_t>(strlen(resp)));
        }
    }
}
