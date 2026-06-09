// knd_client.cpp - see knd_client.h.
#include "knd_client.h"

#include <vector>

KndClient::~KndClient()
{
    close();
}

bool KndClient::open()
{
    if (isOpen()) {
        return true;
    }
    h_ = CreateFileW(KND_DOS_NAME, GENERIC_READ | GENERIC_WRITE,
                     FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                     OPEN_EXISTING, 0, nullptr);
    return isOpen();
}

void KndClient::close()
{
    if (ring_ != nullptr && h_ != INVALID_HANDLE_VALUE) {
        DWORD ret = 0;
        ioctl(IOCTL_KND_UNMAP_RING, nullptr, 0, nullptr, 0, &ret);
    }
    ring_ = nullptr;
    data_ = nullptr;
    dataSize_ = 0;
    mappedSize_ = 0;

    if (h_ != INVALID_HANDLE_VALUE) {
        CloseHandle(h_);          // IRP_MJ_CLEANUP unmaps the ring kernel-side
        h_ = INVALID_HANDLE_VALUE;
    }
}

bool KndClient::ioctl(DWORD code, void* in, DWORD inLen, void* out, DWORD outLen, DWORD* returned)
{
    if (!isOpen()) {
        return false;
    }
    return DeviceIoControl(h_, code, in, inLen, out, outLen, returned, nullptr) != 0;
}

bool KndClient::getVersion(KND_VERSION_OUT& out)
{
    DWORD ret = 0;
    return ioctl(IOCTL_KND_GET_VERSION, nullptr, 0, &out, sizeof(out), &ret) && ret == sizeof(out);
}

bool KndClient::mapRing()
{
    KND_MAP_RING_OUT info{};
    DWORD ret = 0;
    if (!ioctl(IOCTL_KND_MAP_RING, nullptr, 0, &info, sizeof(info), &ret) || ret < sizeof(info)) {
        return false;
    }

    ring_ = reinterpret_cast<KND_RING_HEADER*>(static_cast<uintptr_t>(info.userVa));
    if (ring_ == nullptr || ring_->magic != KND_RING_MAGIC || ring_->version != KND_PROTOCOL_VERSION) {
        ring_ = nullptr;
        return false;
    }
    data_ = reinterpret_cast<uint8_t*>(ring_) + info.dataOffset;
    dataSize_ = info.dataSize;
    mappedSize_ = info.totalSize;
    return true;
}

bool KndClient::startCapture()
{
    DWORD ret = 0;
    return ioctl(IOCTL_KND_START_CAPTURE, nullptr, 0, nullptr, 0, &ret);
}

bool KndClient::stopCapture()
{
    DWORD ret = 0;
    return ioctl(IOCTL_KND_STOP_CAPTURE, nullptr, 0, nullptr, 0, &ret);
}

bool KndClient::getStats(KND_STATS_OUT& out)
{
    DWORD ret = 0;
    return ioctl(IOCTL_KND_GET_STATS, nullptr, 0, &out, sizeof(out), &ret) && ret == sizeof(out);
}

bool KndClient::setRedirect(bool enable, uint16_t proxyPort)
{
    KND_REDIRECT_IN in{};
    in.enable = enable ? 1u : 0u;
    in.proxyPort = proxyPort;
    DWORD ret = 0;
    return ioctl(IOCTL_KND_SET_REDIRECT, &in, sizeof(in), nullptr, 0, &ret);
}

bool KndClient::physRead(uint64_t offset, void* buf, uint32_t len)
{
    if (len == 0 || len > KND_MAX_PHYS_RW) {
        return false;
    }
    KND_PHYS_RW req{};
    req.offset = offset;
    req.length = len;
    DWORD ret = 0;
    return ioctl(IOCTL_KND_PHYS_READ, &req, sizeof(req), buf, len, &ret) && ret == len;
}

bool KndClient::physWrite(uint64_t offset, const void* buf, uint32_t len)
{
    if (len == 0 || len > KND_MAX_PHYS_RW) {
        return false;
    }
    std::vector<uint8_t> in(sizeof(KND_PHYS_RW) + len);
    auto* req = reinterpret_cast<KND_PHYS_RW*>(in.data());
    req->offset = offset;
    req->length = len;
    req->reserved = 0;
    memcpy(in.data() + sizeof(KND_PHYS_RW), buf, len);
    DWORD ret = 0;
    return ioctl(IOCTL_KND_PHYS_WRITE, in.data(), static_cast<DWORD>(in.size()), nullptr, 0, &ret);
}

size_t KndClient::poll(const std::function<void(const KND_RECORD*)>& cb)
{
    if (ring_ == nullptr || data_ == nullptr || dataSize_ == 0) {
        return 0;
    }

    const uint32_t mask = dataSize_ - 1;
    uint64_t wp = ring_->writePos;   // producer-published
    MemoryBarrier();                 // acquire: see record bytes written before wp
    uint64_t rp = ring_->readPos;    // our own position

    size_t count = 0;
    while (rp < wp) {
        uint32_t off = static_cast<uint32_t>(rp & mask);
        const KND_RECORD* rec = reinterpret_cast<const KND_RECORD*>(data_ + off);
        uint32_t len = rec->length;

        // Defensive resync: a valid record is 8-aligned and fits the data area.
        // (Producer guarantees this; a bad value means corruption -> jump to wp.)
        if (len < sizeof(KND_RECORD) || (len & (KND_RECORD_ALIGN - 1)) != 0 || len > dataSize_) {
            rp = wp;
            break;
        }

        if (rec->type != KND_REC_WRAP) {
            cb(rec);
            ++count;
        }
        rp += len;
    }

    MemoryBarrier();                 // release: record reads complete before publish
    ring_->readPos = rp;
    return count;
}
