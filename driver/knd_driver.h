/*
 * knd_driver.h - Driver-wide context and internal prototypes.
 *
 * WDM-style driver (not KMDF): DriverEntry + IoCreateDevice + IRP dispatch, which
 * keeps the WFP callout integration and the user mapping straightforward.
 */

#ifndef KND_DRIVER_H
#define KND_DRIVER_H

#include <ntddk.h>
#include <wdm.h>

/* Pull in the shared driver<->app contract. ntddk/wdm above provide CTL_CODE,
 * the integer typedefs, DECLSPEC_ALIGN and C_ASSERT that the contract relies on. */
#include "knd_protocol.h"

#define KND_POOL_TAG  'rDNK'   /* "KNDr" */

/* Upper bound on simultaneously registered WFP callouts (ALE v4/v6, stream v4/v6,
 * with headroom for datagram/IP-packet layers added in later phases). */
#define KND_MAX_CALLOUTS 8

typedef struct _KND_DEVICE_CONTEXT {
    PDEVICE_OBJECT DeviceObject;

    /* ---- ring cache (the "pool allocated for the driver") ---- */
    PVOID            RingBase;       /* system VA; this is the KND_RING_HEADER */
    SIZE_T           RingTotalSize;  /* headerSize + dataSize, page-multiple */
    ULONG            RingDataSize;   /* power-of-two data-area size */
    PUCHAR           RingData;       /* RingBase + KND_RING_DATA_OFFSET */
    PMDL             RingMdl;        /* describes RingBase, for user mapping */
    KND_RING_HEADER* Ring;          /* == RingBase, typed */

    /* Producer-private authoritative write position. The shared header's
     * writePos is only ever *published* from this and never read back: the
     * consumer has write access to the mapping and could otherwise corrupt
     * the kernel producer's offset arithmetic. */
    ULONGLONG        WritePos;

    /* Producers (WFP callouts on many CPUs) serialize on this; the consumer
     * (usermode app) stays lock-free. Held at <= DISPATCH_LEVEL. */
    KSPIN_LOCK       ProducerLock;

    /* ---- single user mapping of the ring ---- */
    FAST_MUTEX       MapLock;        /* guards the fields below (PASSIVE only) */
    PVOID            UserVa;         /* ring VA in the consumer process, or NULL */
    PEPROCESS        MapProcess;     /* process that owns UserVa */

    /* ---- capture state ---- */
    volatile LONG    CaptureActive;  /* 0/1 */
    volatile LONG64  NextFlowId;
    volatile LONG64  NextSequence;

    /* ---- WFP ---- */
    HANDLE           EngineHandle;          /* FwpmEngineOpen handle */
    BOOLEAN          SublayerAdded;
    UINT32           CalloutIds[KND_MAX_CALLOUTS];  /* FwpsCalloutRegister ids */
    UINT32           NumCallouts;
    BOOLEAN          CalloutsRegistered;
} KND_DEVICE_CONTEXT, *PKND_DEVICE_CONTEXT;

/* Single global context (one device). */
extern PKND_DEVICE_CONTEXT g_Knd;

/* ---- ring.c (producer + lifecycle) ---- */
NTSTATUS KndRingCreate(_Inout_ PKND_DEVICE_CONTEXT ctx, _In_ ULONG dataSize);
VOID     KndRingDestroy(_Inout_ PKND_DEVICE_CONTEXT ctx);

/* Append one record. 'payload' is the type-specific struct (may be NULL/0);
 * 'data' is trailing raw bytes for KND_REC_DATA (may be NULL/0). Returns FALSE
 * (and bumps dropped counters) if the ring is full or the record is too large.
 * Never blocks. Safe to call concurrently and at <= DISPATCH_LEVEL. */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN  KndRingWrite(_Inout_ PKND_DEVICE_CONTEXT ctx,
                      _In_ USHORT type, _In_ USHORT flags,
                      _In_reads_bytes_opt_(payloadLen) const void* payload,
                      _In_ ULONG payloadLen,
                      _In_reads_bytes_opt_(dataLen) const void* data,
                      _In_ ULONG dataLen);

/* Convenience flow-id / sequence allocators. */
__forceinline LONG64 KndNextFlowId(PKND_DEVICE_CONTEXT ctx) {
    return InterlockedIncrement64(&ctx->NextFlowId);
}

/* ---- wfp.c (capture) ---- */
NTSTATUS KndWfpStart(_Inout_ PKND_DEVICE_CONTEXT ctx);
VOID     KndWfpStop(_Inout_ PKND_DEVICE_CONTEXT ctx);

/* ---- ioctl.c (control + mapping + scoped phys R/W) ---- */
NTSTATUS KndMapRingToUser(_Inout_ PKND_DEVICE_CONTEXT ctx, _Out_ KND_MAP_RING_OUT* out);
NTSTATUS KndUnmapRingFromUser(_Inout_ PKND_DEVICE_CONTEXT ctx);

DRIVER_DISPATCH KndDispatchDeviceControl;
DRIVER_DISPATCH KndDispatchCreateClose;

#endif /* KND_DRIVER_H */
