/*
 * ring.c - Single-producer / single-consumer cache ring (kernel producer side).
 *
 * The driver is the producer (WFP callouts, serialized by ProducerLock); the
 * usermode app is the lock-free consumer reading the same memory via an MDL map.
 * Records never straddle the wrap point: if a record won't fit contiguously
 * before end-of-buffer we emit a KND_REC_WRAP pad filling the remainder and
 * restart at offset 0, so the consumer can always cast a record in place.
 */

#include "knd_driver.h"

NTSTATUS
KndRingCreate(_Inout_ PKND_DEVICE_CONTEXT ctx, _In_ ULONG dataSize)
{
    if (dataSize < 0x10000u || (dataSize & (dataSize - 1u)) != 0u) {
        /* require >= 64 KiB and a power of two (for cheap masking) */
        return STATUS_INVALID_PARAMETER;
    }

    ctx->RingTotalSize = (SIZE_T)KND_RING_DATA_OFFSET + dataSize;

    /* Nonpaged so it is always resident and touchable at DISPATCH_LEVEL, and so
     * it can be locked + mapped into usermode. Zeroed by ExAllocatePool2. */
    ctx->RingBase = ExAllocatePool2(POOL_FLAG_NON_PAGED, ctx->RingTotalSize, KND_POOL_TAG);
    if (ctx->RingBase == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ctx->Ring = (KND_RING_HEADER*)ctx->RingBase;
    ctx->RingData = (PUCHAR)ctx->RingBase + KND_RING_DATA_OFFSET;
    ctx->RingDataSize = dataSize;

    ctx->Ring->magic = KND_RING_MAGIC;
    ctx->Ring->version = KND_PROTOCOL_VERSION;
    ctx->Ring->headerSize = KND_RING_DATA_OFFSET;
    ctx->Ring->dataSize = dataSize;
    ctx->Ring->totalSize = ctx->RingTotalSize;
    ctx->Ring->writePos = 0;
    ctx->Ring->readPos = 0;
    ctx->WritePos = 0;          /* authoritative producer position */

    /* MDL over the whole region; built for nonpaged pool so the pages are
     * already locked. ioctl.c maps this into the requesting process. */
    ctx->RingMdl = IoAllocateMdl(ctx->RingBase, (ULONG)ctx->RingTotalSize, FALSE, FALSE, NULL);
    if (ctx->RingMdl == NULL) {
        ExFreePoolWithTag(ctx->RingBase, KND_POOL_TAG);
        ctx->RingBase = NULL;
        ctx->Ring = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    MmBuildMdlForNonPagedPool(ctx->RingMdl);

    KeInitializeSpinLock(&ctx->ProducerLock);
    return STATUS_SUCCESS;
}

VOID
KndRingDestroy(_Inout_ PKND_DEVICE_CONTEXT ctx)
{
    /* Safety net: never unmap+free the ring while a usermode mapping is still live
     * (it would pull pages out from under the consumer). A normal unload has already
     * run IRP_MJ_CLEANUP, which unmaps and clears UserVa. */
    if (ctx->UserVa != NULL) {
        return;
    }
    if (ctx->RingMdl != NULL) {
        IoFreeMdl(ctx->RingMdl);
        ctx->RingMdl = NULL;
    }
    if (ctx->RingBase != NULL) {
        ExFreePoolWithTag(ctx->RingBase, KND_POOL_TAG);
        ctx->RingBase = NULL;
    }
    ctx->Ring = NULL;
    ctx->RingData = NULL;
    ctx->RingDataSize = 0;
    ctx->RingTotalSize = 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
KndRingWrite(_Inout_ PKND_DEVICE_CONTEXT ctx,
             _In_ USHORT type, _In_ USHORT flags,
             _In_reads_bytes_opt_(payloadLen) const void* payload,
             _In_ ULONG payloadLen,
             _In_reads_bytes_opt_(dataLen) const void* data,
             _In_ ULONG dataLen)
{
    KIRQL oldIrql;
    LARGE_INTEGER ts;
    ULONGLONG wp, rp, used, avail;
    ULONG mask, offset, contig, recLen, total, needPad, tail, padBytes;
    KND_RECORD* rec;
    PUCHAR body;

    if (ctx->Ring == NULL) {
        return FALSE;
    }

    /* total bytes this record occupies, header + payload + trailing data, 8-aligned */
    recLen = (ULONG)KND_ALIGN_UP((ULONGLONG)sizeof(KND_RECORD) + payloadLen + dataLen);

    /* A single record can never exceed the data area. */
    if (recLen > ctx->RingDataSize) {
        KeAcquireSpinLock(&ctx->ProducerLock, &oldIrql);
        ctx->Ring->droppedRecords++;
        ctx->Ring->droppedBytes += recLen;
        KeReleaseSpinLock(&ctx->ProducerLock, oldIrql);
        return FALSE;
    }

    KeQuerySystemTimePrecise(&ts);
    mask = ctx->RingDataSize - 1u;

    KeAcquireSpinLock(&ctx->ProducerLock, &oldIrql);

    wp = ctx->WritePos;             /* kernel-private authoritative position */
    rp = ctx->Ring->readPos;        /* consumer-owned AND user-writable: untrusted */

    /* A buggy or hostile consumer could publish rp > wp (which would underflow
     * 'used' and make 'avail' enormous) or an otherwise absurd value. Anything
     * inconsistent is treated as "ring full" so we drop rather than over-trust
     * it and overwrite unread data. (Masking still keeps every write in-bounds,
     * so the worst a bad rp can do is cost us records, never a stray write.) */
    if (rp > wp || (wp - rp) > (ULONGLONG)ctx->RingDataSize) {
        ctx->Ring->droppedRecords++;
        ctx->Ring->droppedBytes += recLen;
        KeReleaseSpinLock(&ctx->ProducerLock, oldIrql);
        return FALSE;
    }
    used = wp - rp;
    avail = (ULONGLONG)ctx->RingDataSize - used;

    offset = (ULONG)(wp & mask);
    contig = ctx->RingDataSize - offset;
    needPad = 0;

    if (recLen <= contig) {
        /* Fits contiguously. If the leftover is too small to ever hold a record
         * header, absorb it into this record so the next write lands at offset 0. */
        tail = contig - recLen;
        if (tail != 0 && tail < sizeof(KND_RECORD)) {
            recLen = contig;
        }
        total = recLen;
    } else {
        /* Must wrap. By the absorb rule above, contig is either the whole buffer
         * or >= sizeof(KND_RECORD) here, so the WRAP header always fits. */
        needPad = contig;
        total = needPad + recLen;
    }

    if (avail < total) {
        ctx->Ring->droppedRecords++;
        ctx->Ring->droppedBytes += total;
        KeReleaseSpinLock(&ctx->ProducerLock, oldIrql);
        return FALSE;
    }

    if (needPad != 0) {
        rec = (KND_RECORD*)(ctx->RingData + offset);
        rec->length = needPad;
        rec->type = (USHORT)KND_REC_WRAP;
        rec->flags = 0;
        rec->sequence = (ULONGLONG)InterlockedIncrement64(&ctx->NextSequence);
        rec->timestamp = ts.QuadPart;
        wp += needPad;
        offset = 0;
    }

    rec = (KND_RECORD*)(ctx->RingData + offset);
    rec->length = recLen;
    rec->type = type;
    rec->flags = flags;
    rec->sequence = (ULONGLONG)InterlockedIncrement64(&ctx->NextSequence);
    rec->timestamp = ts.QuadPart;

    body = (PUCHAR)rec + sizeof(KND_RECORD);
    if (payload != NULL && payloadLen != 0) {
        RtlCopyMemory(body, payload, payloadLen);
        body += payloadLen;
    }
    if (data != NULL && dataLen != 0) {
        RtlCopyMemory(body, data, dataLen);
        body += dataLen;
    }
    /* Zero any alignment padding (and absorbed tail) so we never leak stale pool
     * bytes to the usermode consumer. */
    padBytes = recLen - (ULONG)sizeof(KND_RECORD) - payloadLen - dataLen;
    if (padBytes != 0) {
        RtlZeroMemory(body, padBytes);
    }

    wp += recLen;

    /* Advance the authoritative (kernel-private) position, then publish it.
     * The memory barrier ensures all record bytes are visible before the
     * consumer can observe the new writePos (release semantics). */
    ctx->WritePos = wp;
    KeMemoryBarrier();
    ctx->Ring->writePos = wp;

    ctx->Ring->totalRecords++;
    ctx->Ring->totalBytes += total;

    KeReleaseSpinLock(&ctx->ProducerLock, oldIrql);
    return TRUE;
}
