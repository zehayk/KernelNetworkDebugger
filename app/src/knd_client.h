// knd_client.h - usermode side of the driver contract: open the device, run the
// control IOCTLs, map the shared ring, and consume records lock-free.
#pragma once

#include <windows.h>
#include <winioctl.h>
#include "knd_protocol.h"   // resolved via the ../common include dir

#include <cstdint>
#include <functional>

class KndClient {
public:
    KndClient() = default;
    ~KndClient();

    KndClient(const KndClient&) = delete;
    KndClient& operator=(const KndClient&) = delete;

    bool open();                          // open \\.\KndCap
    void close();
    bool isOpen() const { return h_ != INVALID_HANDLE_VALUE; }

    bool getVersion(KND_VERSION_OUT& out);
    bool mapRing();                       // map the shared cache into this process
    bool startCapture();
    bool stopCapture();
    bool getStats(KND_STATS_OUT& out);

    // Scoped phys R/W over the driver's own cache region (offset, not a PA).
    bool physRead(uint64_t offset, void* buf, uint32_t len);
    bool physWrite(uint64_t offset, const void* buf, uint32_t len);

    // Consume every record produced since the last poll; invokes cb per record
    // (WRAP padding is skipped internally). Returns the number of records seen.
    size_t poll(const std::function<void(const KND_RECORD*)>& cb);

    const KND_RING_HEADER* ring() const { return ring_; }
    bool isMapped() const { return ring_ != nullptr; }

private:
    bool ioctl(DWORD code, void* in, DWORD inLen, void* out, DWORD outLen, DWORD* returned);

    HANDLE            h_         = INVALID_HANDLE_VALUE;
    KND_RING_HEADER*  ring_      = nullptr;   // base of the mapping
    uint8_t*          data_      = nullptr;   // ring_ + dataOffset
    uint32_t          dataSize_  = 0;         // power of two
    uint64_t          mappedSize_= 0;
};
