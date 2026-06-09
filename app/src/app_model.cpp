// app_model.cpp - see app_model.h.
#include "app_model.h"

#include <windows.h>
#include <cstdio>

// ---- helpers ----

static std::string Utf16ToUtf8(const wchar_t* s, int chars)
{
    if (s == nullptr || chars <= 0) {
        return std::string();
    }
    int n = WideCharToMultiByte(CP_UTF8, 0, s, chars, nullptr, 0, nullptr, nullptr);
    if (n <= 0) {
        return std::string();
    }
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, s, chars, out.data(), n, nullptr, nullptr);
    return out;
}

std::string KndFormatAddr(const uint8_t addr[16], uint8_t ipVersion)
{
    char buf[64];
    if (ipVersion == KND_IPV6) {
        std::snprintf(buf, sizeof(buf),
                      "%x:%x:%x:%x:%x:%x:%x:%x",
                      (addr[0] << 8) | addr[1], (addr[2] << 8) | addr[3],
                      (addr[4] << 8) | addr[5], (addr[6] << 8) | addr[7],
                      (addr[8] << 8) | addr[9], (addr[10] << 8) | addr[11],
                      (addr[12] << 8) | addr[13], (addr[14] << 8) | addr[15]);
    } else {
        std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
    }
    return buf;
}

std::string KndFormatProto(uint8_t protocol)
{
    switch (protocol) {
    case KND_PROTO_TCP: return "TCP";
    case KND_PROTO_UDP: return "UDP";
    default: {
        char b[16];
        std::snprintf(b, sizeof(b), "ip:%u", protocol);
        return b;
    }
    }
}

std::string KndFormatTime(int64_t ticks100ns)
{
    FILETIME ft;
    ft.dwLowDateTime  = static_cast<DWORD>(static_cast<uint64_t>(ticks100ns) & 0xFFFFFFFFu);
    ft.dwHighDateTime = static_cast<DWORD>(static_cast<uint64_t>(ticks100ns) >> 32);

    FILETIME lft;
    SYSTEMTIME st;
    if (!FileTimeToLocalFileTime(&ft, &lft) || !FileTimeToSystemTime(&lft, &st)) {
        return "--:--:--";
    }
    unsigned ms = static_cast<unsigned>((static_cast<uint64_t>(ticks100ns) / 10000ull) % 1000ull);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%02u:%02u:%02u.%03u", st.wHour, st.wMinute, st.wSecond, ms);
    return buf;
}

std::string KndFormatBytes(uint64_t n)
{
    const char* units[] = { "B", "KB", "MB", "GB", "TB" };
    double v = static_cast<double>(n);
    int u = 0;
    while (v >= 1024.0 && u < 4) { v /= 1024.0; ++u; }
    char buf[32];
    if (u == 0) {
        std::snprintf(buf, sizeof(buf), "%llu B", static_cast<unsigned long long>(n));
    } else {
        std::snprintf(buf, sizeof(buf), "%.1f %s", v, units[u]);
    }
    return buf;
}

// ---- model ----

KndFlow& KndModel::getOrCreate(uint64_t flowId, double now)
{
    auto it = index_.find(flowId);
    if (it != index_.end()) {
        return flows_[it->second];
    }
    KndFlow f;
    f.flowId = flowId;
    f.uiCreated = now;
    f.uiActivity = now;
    flows_.push_back(std::move(f));
    index_[flowId] = flows_.size() - 1;
    return flows_.back();
}

KndFlow* KndModel::find(uint64_t flowId)
{
    auto it = index_.find(flowId);
    return it == index_.end() ? nullptr : &flows_[it->second];
}

void KndModel::clear()
{
    flows_.clear();
    index_.clear();
    stats_ = KndModelStats{};
    packets_.clear();
    packetNo_ = 0;
}

void KndModel::pushPacket(const KND_RECORD* rec, const KndFlow& f, uint8_t dir,
                          uint32_t len, const uint8_t* data)
{
    KndPacket p;
    p.no = ++packetNo_;
    p.ts = rec->timestamp;
    p.flowId = f.flowId;
    p.type = rec->type;
    p.direction = dir;
    p.length = len;

    const char* proc = f.processName.empty() ? "" : f.processName.c_str();
    std::string remote = KndFormatAddr(f.remoteAddr, f.ipVersion);
    char head[160];

    if (rec->type == KND_REC_CONN_OPEN) {
        std::snprintf(head, sizeof(head), "Connect  %s:%u  %s", remote.c_str(), f.remotePort, proc);
        p.info = head;
    } else if (rec->type == KND_REC_CONN_CLOSE) {
        std::snprintf(head, sizeof(head), "Close  %s:%u", remote.c_str(), f.remotePort);
        p.info = head;
    } else {
        uint32_t pv = (len < 64) ? len : 64;
        if (data != nullptr && pv > 0) { p.preview.assign(data, data + pv); }
        std::string text;
        for (uint32_t i = 0; i < pv && i < 48; ++i) {
            unsigned char c = data[i];
            text += (c >= 0x20 && c < 0x7f) ? (char)c : '.';
        }
        const char* arrow = (dir == KND_DIR_INBOUND) ? "<-" : "->";
        std::snprintf(head, sizeof(head), "%s  %u B  ", arrow, len);
        p.info = std::string(head) + text;
    }

    packets_.push_back(std::move(p));
    if (packets_.size() > packetCap) { packets_.pop_front(); }
}

void KndModel::ingest(const KND_RECORD* rec, double now)
{
    stats_.totalRecords++;

    const uint8_t* body = reinterpret_cast<const uint8_t*>(rec) + sizeof(KND_RECORD);

    switch (rec->type) {
    case KND_REC_CONN_OPEN: {
        const auto* p = reinterpret_cast<const KND_CONN_PAYLOAD*>(body);
        KndFlow& f = getOrCreate(p->flowId, now);
        f.processId  = p->processId;
        f.protocol   = p->protocol;
        f.ipVersion  = p->ipVersion;
        f.direction  = p->direction;
        f.localPort  = p->localPort;
        f.remotePort = p->remotePort;
        memcpy(f.localAddr, p->localAddr, 16);
        memcpy(f.remoteAddr, p->remoteAddr, 16);
        if (f.firstTs == 0) { f.firstTs = rec->timestamp; }
        f.lastTs = rec->timestamp;
        if (p->processPathChars > 0) {
            f.processPath = Utf16ToUtf8(p->processPath, p->processPathChars);
            size_t slash = f.processPath.find_last_of("\\/");
            f.processName = (slash == std::string::npos) ? f.processPath
                                                         : f.processPath.substr(slash + 1);
        }
        pushPacket(rec, f, f.direction, 0, nullptr);
        stats_.connOpens++;
        break;
    }

    case KND_REC_CONN_CLOSE: {
        const auto* p = reinterpret_cast<const KND_CONN_PAYLOAD*>(body);
        KndFlow& f = getOrCreate(p->flowId, now);
        f.closed = true;
        f.bytesIn  = p->bytesIn;
        f.bytesOut = p->bytesOut;
        f.lastTs = rec->timestamp;
        pushPacket(rec, f, 0, 0, nullptr);
        stats_.connCloses++;
        break;
    }

    case KND_REC_DATA: {
        const auto* dp = reinterpret_cast<const KND_DATA_PAYLOAD*>(body);
        const uint8_t* data = body + sizeof(KND_DATA_PAYLOAD);
        KndFlow& f = getOrCreate(dp->flowId, now);
        int dir = (dp->direction == KND_DIR_INBOUND) ? 1 : 0;

        if (dir == 1) { f.bytesIn += dp->dataLength; } else { f.bytesOut += dp->dataLength; }
        f.records++;
        f.lastTs = rec->timestamp;
        f.uiActivity = now;

        auto& buf = f.payload[dir];
        if (buf.size() < payloadCap) {
            size_t room = payloadCap - buf.size();
            size_t take = (dp->dataLength < room) ? dp->dataLength : room;
            buf.insert(buf.end(), data, data + take);
            if (take < dp->dataLength) { f.truncated[dir] = true; }
        } else {
            f.truncated[dir] = true;
        }

        if (dir == 1) { stats_.inBytes += dp->dataLength; } else { stats_.outBytes += dp->dataLength; }
        {
            uint32_t L = dp->dataLength;
            int b = (L < 128) ? 0 : (L < 512) ? 1 : (L < 1500) ? 2 : (L < 4096) ? 3 : (L < 16384) ? 4 : 5;
            stats_.sizeHist[b]++;
        }
        pushPacket(rec, f, dp->direction, dp->dataLength, data);
        stats_.dataRecords++;
        stats_.payloadBytes += dp->dataLength;
        break;
    }

    default:
        break;
    }
}
