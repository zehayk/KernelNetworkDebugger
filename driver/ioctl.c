/*
 * ioctl.c - Control plane: IOCTL dispatch, ring mapping into the consumer, and
 * the *scoped* physical read/write.
 *
 * The real zero-copy read path is the MDL-mapped ring (IOCTL_KND_MAP_RING). The
 * phys R/W IOCTLs are deliberately limited to the driver's OWN cache region:
 * the caller passes an OFFSET into that region (not a physical address), we
 * bounds-check it, then translate the resulting kernel VA to a physical address
 * per page (nonpaged pool is not physically contiguous). This is intentionally
 * NOT an arbitrary physical R/W primitive, which would be a BYOVD-class hole.
 */

#include "knd_driver.h"

/* ---- ring <-> usermode mapping ---- */

NTSTATUS
KndMapRingToUser(_Inout_ PKND_DEVICE_CONTEXT ctx, _Out_ KND_MAP_RING_OUT* out)
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID va = NULL;

    if (ctx->RingMdl == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    ExAcquireFastMutex(&ctx->MapLock);

    if (ctx->UserVa != NULL) {
        /* One consumer at a time. If it's the same process re-asking, hand back
         * the existing mapping; otherwise the device is busy. */
        if (ctx->MapProcess == PsGetCurrentProcess()) {
            va = ctx->UserVa;
        } else {
            ExReleaseFastMutex(&ctx->MapLock);
            return STATUS_DEVICE_BUSY;
        }
    } else {
        __try {
            va = MmMapLockedPagesSpecifyCache(ctx->RingMdl, UserMode, MmCached,
                                              NULL, FALSE, NormalPagePriority);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            va = NULL;
            status = GetExceptionCode();
        }

        if (va == NULL) {
            ExReleaseFastMutex(&ctx->MapLock);
            return NT_SUCCESS(status) ? STATUS_INSUFFICIENT_RESOURCES : status;
        }

        ctx->UserVa = va;
        ctx->MapProcess = PsGetCurrentProcess();
    }

    out->userVa = (ULONGLONG)(ULONG_PTR)va;
    out->totalSize = ctx->RingTotalSize;
    out->dataOffset = KND_RING_DATA_OFFSET;
    out->dataSize = ctx->RingDataSize;

    ExReleaseFastMutex(&ctx->MapLock);
    return STATUS_SUCCESS;
}

NTSTATUS
KndUnmapRingFromUser(_Inout_ PKND_DEVICE_CONTEXT ctx)
{
    /* MmUnmapLockedPages must run in the context of the process that owns the
     * mapping, so this is driven from IRP_MJ_CLEANUP (issued in that process). */
    ExAcquireFastMutex(&ctx->MapLock);
    if (ctx->UserVa != NULL && ctx->MapProcess == PsGetCurrentProcess()) {
        MmUnmapLockedPages(ctx->UserVa, ctx->RingMdl);
        ctx->UserVa = NULL;
        ctx->MapProcess = NULL;
    }
    ExReleaseFastMutex(&ctx->MapLock);
    return STATUS_SUCCESS;
}

/* ---- scoped physical copy over the driver's own cache region ---- */

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
KndScopedPhysCopy(_In_ PKND_DEVICE_CONTEXT ctx, _In_ ULONGLONG offset,
                  _In_ ULONG length, _Inout_updates_bytes_(length) PVOID buffer,
                  _In_ BOOLEAN isWrite)
{
    PUCHAR va;
    PUCHAR ptr;
    ULONG  remaining;

    if (ctx->RingBase == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }
    if (length == 0 || length > KND_MAX_PHYS_RW) {
        return STATUS_INVALID_PARAMETER;
    }
    /* overflow-safe containment within [0, RingTotalSize) */
    if (offset >= ctx->RingTotalSize || (ULONGLONG)length > ctx->RingTotalSize - offset) {
        return STATUS_INVALID_PARAMETER;
    }

    va = (PUCHAR)ctx->RingBase + offset;
    ptr = (PUCHAR)buffer;
    remaining = length;

    while (remaining > 0) {
        ULONG pageOff = (ULONG)((ULONG_PTR)va & (PAGE_SIZE - 1));
        ULONG chunk = PAGE_SIZE - pageOff;
        PHYSICAL_ADDRESS pa;

        if (chunk > remaining) {
            chunk = remaining;
        }

        /* The required VA -> PA translation. Pool pages are scattered, so this
         * happens per page. */
        pa = MmGetPhysicalAddress(va);
        if (pa.QuadPart == 0) {
            return STATUS_UNSUCCESSFUL;
        }

        if (isWrite) {
            /* Apply to our own pool through the validated, owned kernel VA.
             * (The PA was computed above to honor the translation contract;
             * writing RAM through an MmMapIoSpace alias is discouraged.) */
            RtlCopyMemory(va, ptr, chunk);
        } else {
            MM_COPY_ADDRESS src;
            SIZE_T copied = 0;
            NTSTATUS s;

            src.PhysicalAddress = pa;
            s = MmCopyMemory(ptr, src, chunk, MM_COPY_MEMORY_PHYSICAL, &copied);
            if (!NT_SUCCESS(s)) {
                return s;
            }
            if (copied != chunk) {
                return STATUS_UNSUCCESSFUL;
            }
        }

        va += chunk;
        ptr += chunk;
        remaining -= chunk;
    }

    return STATUS_SUCCESS;
}

/* ---- dispatch ---- */

static VOID
KndCompleteIrp(_Inout_ PIRP Irp, _In_ NTSTATUS Status, _In_ ULONG_PTR Information)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
NTSTATUS
KndDispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    PKND_DEVICE_CONTEXT ctx = g_Knd;
    PVOID sysBuf = Irp->AssociatedIrp.SystemBuffer;
    ULONG inLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG code = irpSp->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (ctx == NULL) {
        KndCompleteIrp(Irp, STATUS_DEVICE_NOT_READY, 0);
        return STATUS_DEVICE_NOT_READY;
    }

    switch (code) {
    case IOCTL_KND_GET_VERSION: {
        if (outLen < sizeof(KND_VERSION_OUT)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        KND_VERSION_OUT* v = (KND_VERSION_OUT*)sysBuf;
        v->protocolVersion = KND_PROTOCOL_VERSION;
        v->driverVersion = KND_DRIVER_VERSION;
        info = sizeof(*v);
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_KND_MAP_RING: {
        if (outLen < sizeof(KND_MAP_RING_OUT)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        status = KndMapRingToUser(ctx, (KND_MAP_RING_OUT*)sysBuf);
        if (NT_SUCCESS(status)) { info = sizeof(KND_MAP_RING_OUT); }
        break;
    }

    case IOCTL_KND_UNMAP_RING:
        status = KndUnmapRingFromUser(ctx);
        break;

    case IOCTL_KND_START_CAPTURE:
        InterlockedExchange(&ctx->CaptureActive, 1);
        if (ctx->Ring != NULL) { ctx->Ring->captureActive = 1; }
        status = STATUS_SUCCESS;
        break;

    case IOCTL_KND_STOP_CAPTURE:
        InterlockedExchange(&ctx->CaptureActive, 0);
        if (ctx->Ring != NULL) { ctx->Ring->captureActive = 0; }
        status = STATUS_SUCCESS;
        break;

    case IOCTL_KND_SET_REDIRECT: {
        if (inLen < sizeof(KND_REDIRECT_IN)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        KND_REDIRECT_IN* rq = (KND_REDIRECT_IN*)sysBuf;
        ctx->RedirectPort = rq->proxyPort;
        InterlockedExchange(&ctx->RedirectEnable, rq->enable ? 1 : 0);
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_KND_GET_STATS: {
        if (outLen < sizeof(KND_STATS_OUT)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        if (ctx->Ring == NULL) { status = STATUS_DEVICE_NOT_READY; break; }
        KND_STATS_OUT* st = (KND_STATS_OUT*)sysBuf;
        st->writePos = ctx->Ring->writePos;
        st->readPos = ctx->Ring->readPos;
        st->totalRecords = ctx->Ring->totalRecords;
        st->droppedRecords = ctx->Ring->droppedRecords;
        st->totalBytes = ctx->Ring->totalBytes;
        st->droppedBytes = ctx->Ring->droppedBytes;
        st->activeFlows = ctx->Ring->activeFlows;
        st->captureActive = ctx->Ring->captureActive;
        info = sizeof(*st);
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_KND_PHYS_READ: {
        KND_PHYS_RW req;
        if (inLen < sizeof(KND_PHYS_RW)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        /* snapshot the request before we overwrite the shared buffer with output */
        req = *(KND_PHYS_RW*)sysBuf;
        if (req.length == 0 || req.length > KND_MAX_PHYS_RW) { status = STATUS_INVALID_PARAMETER; break; }
        if (outLen < req.length) { status = STATUS_BUFFER_TOO_SMALL; break; }
        status = KndScopedPhysCopy(ctx, req.offset, req.length, sysBuf, FALSE);
        if (NT_SUCCESS(status)) { info = req.length; }
        break;
    }

    case IOCTL_KND_PHYS_WRITE: {
        KND_PHYS_RW* req = (KND_PHYS_RW*)sysBuf;
        if (inLen < sizeof(KND_PHYS_RW)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        if (req->length == 0 || req->length > KND_MAX_PHYS_RW) { status = STATUS_INVALID_PARAMETER; break; }
        if (inLen < sizeof(KND_PHYS_RW) + req->length) { status = STATUS_BUFFER_TOO_SMALL; break; }
        status = KndScopedPhysCopy(ctx, req->offset, req->length,
                                   (PUCHAR)sysBuf + sizeof(KND_PHYS_RW), TRUE);
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    KndCompleteIrp(Irp, status, info);
    return status;
}

_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLEANUP)
_Dispatch_type_(IRP_MJ_CLOSE)
NTSTATUS
KndDispatchCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

    UNREFERENCED_PARAMETER(DeviceObject);

    if (irpSp->MajorFunction == IRP_MJ_CLEANUP && g_Knd != NULL) {
        /* runs in the owning process context -> safe place to unmap the ring */
        KndUnmapRingFromUser(g_Knd);
    }

    KndCompleteIrp(Irp, STATUS_SUCCESS, 0);
    return STATUS_SUCCESS;
}
