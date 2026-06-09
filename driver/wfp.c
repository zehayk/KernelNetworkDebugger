/*
 * wfp.c - WFP capture: connection lifecycle (ALE FLOW_ESTABLISHED) + reassembled
 * TCP payload (STREAM layer), feeding KndRingWrite. Purely passive: filters are
 * inspection callouts that return CONTINUE/PERMIT, so traffic is never blocked or
 * modified. Loopback is visible at these layers (covers port-hijack/localhost).
 *
 * NOTE: written against the standard WFP kernel API. It has NOT been compiled
 * against a WDK here; a few symbol spellings (field-index enums, callout FN
 * version, stream action constants) must be confirmed on the first build inside
 * the VM's WDK environment. The structure and flow are the conventional ones.
 *
 * Links: fwpkclnt.lib, ndis.lib, uuid.lib.
 */

/* INITGUID must precede the headers that declare FWPM_LAYER_* so the GUID
 * symbols are instantiated in this (single) translation unit. */
#include <initguid.h>
#include "knd_driver.h"
#include <fwpsk.h>
#include <fwpmk.h>

#define KND_STREAM_COPY_MAX (256u * 1024u)  /* cap copied per stream indication */

/* ---- our WFP object GUIDs (unique to this driver) ---- */
/* {6F1A3C20-9E44-4B0E-9C2A-3D7F1B2E5A01} */
static const GUID KND_SUBLAYER_GUID =
    { 0x6f1a3c20, 0x9e44, 0x4b0e, { 0x9c, 0x2a, 0x3d, 0x7f, 0x1b, 0x2e, 0x5a, 0x01 } };
/* {6F1A3C21-...} flow established v4 */
static const GUID KND_CO_FLOW_V4 =
    { 0x6f1a3c21, 0x9e44, 0x4b0e, { 0x9c, 0x2a, 0x3d, 0x7f, 0x1b, 0x2e, 0x5a, 0x02 } };
static const GUID KND_CO_FLOW_V6 =
    { 0x6f1a3c22, 0x9e44, 0x4b0e, { 0x9c, 0x2a, 0x3d, 0x7f, 0x1b, 0x2e, 0x5a, 0x03 } };
static const GUID KND_CO_STREAM_V4 =
    { 0x6f1a3c23, 0x9e44, 0x4b0e, { 0x9c, 0x2a, 0x3d, 0x7f, 0x1b, 0x2e, 0x5a, 0x04 } };
static const GUID KND_CO_STREAM_V6 =
    { 0x6f1a3c24, 0x9e44, 0x4b0e, { 0x9c, 0x2a, 0x3d, 0x7f, 0x1b, 0x2e, 0x5a, 0x05 } };

/* {6F1A3C25-...} ALE connect-redirect v4 */
static const GUID KND_CO_REDIRECT_V4 =
    { 0x6f1a3c25, 0x9e44, 0x4b0e, { 0x9c, 0x2a, 0x3d, 0x7f, 0x1b, 0x2e, 0x5a, 0x06 } };
/* {6F1A3C26-...} provider for FwpsRedirectHandleCreate0 */
static const GUID KND_REDIRECT_PROVIDER =
    { 0x6f1a3c26, 0x9e44, 0x4b0e, { 0x9c, 0x2a, 0x3d, 0x7f, 0x1b, 0x2e, 0x5a, 0x07 } };

/* Runtime ids of the stream callouts, needed to associate flow context from the
 * ALE flow-established callout so the (conditional-on-flow) stream callout fires. */
static UINT32 g_streamIdV4 = 0;
static UINT32 g_streamIdV6 = 0;

#define KND_AF_INET           2
#define KND_INADDR_LOOPBACK   0x7f000001UL

/* ---- helpers ---- */

static VOID
KndFillProcessInfo(_In_ const FWPS_INCOMING_METADATA_VALUES0* meta, _Inout_ KND_CONN_PAYLOAD* p)
{
    if (FWPS_IS_METADATA_FIELD_PRESENT(meta, FWPS_METADATA_FIELD_PROCESS_ID)) {
        p->processId = meta->processId;
    }
    if (FWPS_IS_METADATA_FIELD_PRESENT(meta, FWPS_METADATA_FIELD_PROCESS_PATH) &&
        meta->processPath != NULL && meta->processPath->data != NULL) {
        ULONG bytes = meta->processPath->size;
        ULONG chars = bytes / sizeof(WCHAR);
        if (chars > KND_PROCPATH_CHARS - 1) {
            chars = KND_PROCPATH_CHARS - 1;
        }
        RtlCopyMemory(p->processPath, meta->processPath->data, chars * sizeof(WCHAR));
        p->processPath[chars] = L'\0';
        p->processPathChars = (USHORT)chars;
    }
}

/* ---- classify: ALE FLOW_ESTABLISHED (connection open) ---- */

static VOID NTAPI
KndClassifyFlow(_In_ const FWPS_INCOMING_VALUES0* inFixed,
                _In_ const FWPS_INCOMING_METADATA_VALUES0* inMeta,
                _Inout_opt_ void* layerData,
                _In_opt_ const void* classifyContext,
                _In_ const FWPS_FILTER1* filter,
                _In_ UINT64 flowContext,
                _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    PKND_DEVICE_CONTEXT ctx = g_Knd;
    KND_CONN_PAYLOAD p;
    BOOLEAN isV4;

    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    /* never block: continue the filter chain */
    if (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) {
        classifyOut->actionType = FWP_ACTION_CONTINUE;
    }

    if (ctx == NULL || ctx->CaptureActive == 0) {
        return;
    }

    RtlZeroMemory(&p, sizeof(p));
    isV4 = (inFixed->layerId == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4);

    if (isV4) {
        ULONG la = inFixed->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS].value.uint32;
        ULONG ra = inFixed->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS].value.uint32;
        p.ipVersion = KND_IPV4;
        /* WFP gives v4 addresses as host-order UINT32; store as network-order octets */
        p.localAddr[0]  = (UCHAR)(la >> 24); p.localAddr[1] = (UCHAR)(la >> 16);
        p.localAddr[2]  = (UCHAR)(la >> 8);  p.localAddr[3] = (UCHAR)(la);
        p.remoteAddr[0] = (UCHAR)(ra >> 24); p.remoteAddr[1] = (UCHAR)(ra >> 16);
        p.remoteAddr[2] = (UCHAR)(ra >> 8);  p.remoteAddr[3] = (UCHAR)(ra);
        p.localPort  = inFixed->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT].value.uint16;
        p.remotePort = inFixed->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT].value.uint16;
        p.protocol   = inFixed->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL].value.uint8;
        p.direction  = (inFixed->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_DIRECTION].value.uint32
                        == FWP_DIRECTION_INBOUND) ? KND_DIR_INBOUND : KND_DIR_OUTBOUND;
    } else {
        const FWP_BYTE_ARRAY16* la = inFixed->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_ADDRESS].value.byteArray16;
        const FWP_BYTE_ARRAY16* ra = inFixed->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_ADDRESS].value.byteArray16;
        p.ipVersion = KND_IPV6;
        if (la) { RtlCopyMemory(p.localAddr, la->byteArray16, 16); }
        if (ra) { RtlCopyMemory(p.remoteAddr, ra->byteArray16, 16); }
        p.localPort  = inFixed->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_PORT].value.uint16;
        p.remotePort = inFixed->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_PORT].value.uint16;
        p.protocol   = inFixed->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_PROTOCOL].value.uint8;
        p.direction  = (inFixed->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_DIRECTION].value.uint32
                        == FWP_DIRECTION_INBOUND) ? KND_DIR_INBOUND : KND_DIR_OUTBOUND;
    }

    /* Use the WFP flow handle as the stable flow id so STREAM data correlates. */
    UINT64 flowHandle = 0;
    if (FWPS_IS_METADATA_FIELD_PRESENT(inMeta, FWPS_METADATA_FIELD_FLOW_HANDLE)) {
        flowHandle = inMeta->flowHandle;
        p.flowId = flowHandle;
    } else {
        p.flowId = (ULONGLONG)KndNextFlowId(ctx);
    }

    KndFillProcessInfo(inMeta, &p);

    if (KndRingWrite(ctx, (USHORT)KND_REC_CONN_OPEN, 0, &p, sizeof(p), NULL, 0)) {
        InterlockedIncrement((volatile LONG*)&ctx->Ring->activeFlows);
    }

    /* Associate our flow id as the stream-layer context. This is what makes the
     * conditional-on-flow STREAM callout actually fire for this connection and lets
     * it correlate its data + get a flow-delete notification (-> CONN_CLOSE). */
    if (flowHandle != 0) {
        UINT32 sid = isV4 ? g_streamIdV4 : g_streamIdV6;
        UINT16 streamLayer = isV4 ? (UINT16)FWPS_LAYER_STREAM_V4 : (UINT16)FWPS_LAYER_STREAM_V6;
        if (sid != 0) {
            FwpsFlowAssociateContext0(flowHandle, streamLayer, sid, (UINT64)p.flowId);
        }
    }
}

/* ---- classify: STREAM (reassembled TCP payload) ---- */

static VOID NTAPI
KndClassifyStream(_In_ const FWPS_INCOMING_VALUES0* inFixed,
                  _In_ const FWPS_INCOMING_METADATA_VALUES0* inMeta,
                  _Inout_opt_ void* layerData,
                  _In_opt_ const void* classifyContext,
                  _In_ const FWPS_FILTER1* filter,
                  _In_ UINT64 flowContext,
                  _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    PKND_DEVICE_CONTEXT ctx = g_Knd;
    FWPS_STREAM_CALLOUT_IO_PACKET0* pkt = (FWPS_STREAM_CALLOUT_IO_PACKET0*)layerData;
    FWPS_STREAM_DATA0* sd;
    PUCHAR scratch;
    SIZE_T copyLen, got = 0;
    ULONGLONG flowId;
    UCHAR direction;
    USHORT recFlags = 0;
    ULONG off;

    UNREFERENCED_PARAMETER(inFixed);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);

    if (pkt == NULL || pkt->streamData == NULL) {
        if (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) {
            classifyOut->actionType = FWP_ACTION_PERMIT;
        }
        return;
    }

    sd = pkt->streamData;

    /* pass everything through unmodified */
    pkt->streamAction = FWPS_STREAM_ACTION_NONE;
    pkt->countBytesEnforced = sd->dataLength;
    if (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
    }

    if (ctx == NULL || ctx->CaptureActive == 0 || sd->dataLength == 0) {
        return;
    }

    direction = (sd->flags & FWPS_STREAM_FLAG_RECEIVE) ? KND_DIR_INBOUND : KND_DIR_OUTBOUND;

    /* flowContext is the id we associated at flow-establishment; fall back to the
     * metadata flow handle if (unexpectedly) absent. */
    flowId = (flowContext != 0)
                 ? flowContext
                 : (FWPS_IS_METADATA_FIELD_PRESENT(inMeta, FWPS_METADATA_FIELD_FLOW_HANDLE)
                        ? inMeta->flowHandle : 0);

    copyLen = sd->dataLength;
    if (copyLen > KND_STREAM_COPY_MAX) {
        copyLen = KND_STREAM_COPY_MAX;
        recFlags |= 0x0001; /* truncated indication */
    }

    scratch = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, copyLen, KND_POOL_TAG);
    if (scratch == NULL) {
        return; /* drop this indication; traffic still flows */
    }

    FwpsCopyStreamDataToBuffer0(sd, scratch, copyLen, &got);

    /* Emit in <= KND_MAX_DATA_CHUNK records so each fits the ring's chunk rule. */
    for (off = 0; off < (ULONG)got; ) {
        KND_DATA_PAYLOAD dp;
        ULONG chunk = (ULONG)got - off;
        if (chunk > KND_MAX_DATA_CHUNK) {
            chunk = KND_MAX_DATA_CHUNK;
        }
        RtlZeroMemory(&dp, sizeof(dp));
        dp.flowId = flowId;
        dp.direction = direction;
        dp.dataKind = (UCHAR)KND_DATA_CIPHERTEXT;
        dp.dataLength = chunk;
        KndRingWrite(ctx, (USHORT)KND_REC_DATA, recFlags, &dp, sizeof(dp), scratch + off, chunk);
        off += chunk;
    }

    ExFreePoolWithTag(scratch, KND_POOL_TAG);
}

/* ---- classify: ALE CONNECT_REDIRECT (transparent redirect to the proxy) ----
 * Rewrites outbound TCP :443/:80 to 127.0.0.1:proxyPort and stashes the original
 * destination in a localRedirectContext the proxy reads back. v4 only for now.
 * NOTE: written to the standard WFP proxy-redirect pattern but NOT runtime-tested
 * (driver runs only in the VM); confirm field enums + FWPS_CONNECT_REQUEST0 layout
 * on first run, and the localRedirectContext lifetime. */
static void NTAPI
KndClassifyConnectRedirect(_In_ const FWPS_INCOMING_VALUES0* inFixed,
                           _In_ const FWPS_INCOMING_METADATA_VALUES0* inMeta,
                           _Inout_opt_ void* layerData,
                           _In_opt_ const void* classifyContext,
                           _In_ const FWPS_FILTER1* filter,
                           _In_ UINT64 flowContext,
                           _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    PKND_DEVICE_CONTEXT ctx = g_Knd;
    UINT64 classifyHandle = 0;
    FWPS_CONNECT_REQUEST0* req = NULL;
    NTSTATUS status;
    UINT8 proto;
    UINT16 remotePort;

    UNREFERENCED_PARAMETER(inMeta);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(flowContext);

    if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE)) { return; }
    classifyOut->actionType = FWP_ACTION_PERMIT;

    if (ctx == NULL || ctx->RedirectEnable == 0 || !ctx->RedirectHandleCreated) { return; }

    proto = inFixed->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL].value.uint8;
    remotePort = inFixed->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT].value.uint16;
    if (proto != KND_PROTO_TCP) { return; }
    if (remotePort != 443 && remotePort != 80) { return; }
    if (remotePort == ctx->RedirectPort) { return; }   /* avoid redirect loops */

    status = FwpsAcquireClassifyHandle0((void*)classifyContext, 0, &classifyHandle);
    if (!NT_SUCCESS(status)) { return; }

    status = FwpsAcquireWritableLayerDataPointer0(classifyHandle, filter->filterId, 0,
                                                  (PVOID*)&req, classifyOut);
    if (!NT_SUCCESS(status) || req == NULL) {
        FwpsReleaseClassifyHandle0(classifyHandle);
        return;
    }

    {
        KND_REDIRECT_CTX* rc = (KND_REDIRECT_CTX*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*rc), KND_POOL_TAG);
        if (rc != NULL) {
            ULONG ra = inFixed->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS].value.uint32;
            UCHAR* sa = (UCHAR*)&req->remoteAddressAndPort;
            USHORT netPort = RtlUshortByteSwap(ctx->RedirectPort);
            ULONG  netLoop = RtlUlongByteSwap(KND_INADDR_LOOPBACK);

            RtlZeroMemory(rc, sizeof(*rc));
            rc->ipVersion = KND_IPV4;
            rc->origPort = remotePort;
            rc->origAddr[0] = (UCHAR)(ra >> 24); rc->origAddr[1] = (UCHAR)(ra >> 16);
            rc->origAddr[2] = (UCHAR)(ra >> 8);  rc->origAddr[3] = (UCHAR)ra;

            /* remoteAddressAndPort is a SOCKADDR_STORAGE: family(2) port(2,net) addr(4,net) */
            RtlZeroMemory(sa, sizeof(req->remoteAddressAndPort));
            *(USHORT*)(sa + 0) = KND_AF_INET;
            RtlCopyMemory(sa + 2, &netPort, 2);
            RtlCopyMemory(sa + 4, &netLoop, 4);

            req->localRedirectHandle = ctx->RedirectHandle;
            req->localRedirectContext = rc;
            req->localRedirectContextSize = sizeof(*rc);
        }
    }

    FwpsApplyModifiedLayerData0(classifyHandle, req, 0);
    FwpsReleaseClassifyHandle0(classifyHandle);
}

/* ---- flow delete: connection torn down -> CONN_CLOSE ---- */

static void NTAPI
KndFlowDelete(UINT16 layerId, UINT32 calloutId, UINT64 flowContext)
{
    PKND_DEVICE_CONTEXT ctx = g_Knd;
    KND_CONN_PAYLOAD p;

    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);

    if (ctx == NULL || ctx->CaptureActive == 0) {
        return;
    }
    RtlZeroMemory(&p, sizeof(p));
    p.flowId = flowContext;
    if (KndRingWrite(ctx, (USHORT)KND_REC_CONN_CLOSE, 0, &p, sizeof(p), NULL, 0)) {
        InterlockedDecrement((volatile LONG*)&ctx->Ring->activeFlows);
    }
}

/* ---- notify (required, no-op) ---- */

static NTSTATUS NTAPI
KndNotifyFn(_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
            _In_ const GUID* filterKey,
            _Inout_ FWPS_FILTER1* filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

/* ---- registration helpers ---- */

static NTSTATUS
KndRegisterCallout(_Inout_ PKND_DEVICE_CONTEXT ctx, _In_ const GUID* key,
                   _In_ FWPS_CALLOUT_CLASSIFY_FN1 classifyFn, _In_ const wchar_t* name,
                   _In_ const GUID* layerKey, _In_ UINT32 actionType,
                   _In_opt_ FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN flowDeleteFn,
                   _In_ UINT32 flags, _Out_opt_ UINT32* outCalloutId)
{
    FWPS_CALLOUT1 sCallout;
    FWPM_CALLOUT0 mCallout;
    FWPM_FILTER0 filter;
    UINT32 calloutId = 0;
    NTSTATUS status;

    RtlZeroMemory(&sCallout, sizeof(sCallout));
    sCallout.calloutKey = *key;
    sCallout.flags = flags;
    sCallout.classifyFn = classifyFn;
    sCallout.notifyFn = KndNotifyFn;
    sCallout.flowDeleteFn = flowDeleteFn;

    status = FwpsCalloutRegister1(ctx->DeviceObject, &sCallout, &calloutId);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (outCalloutId != NULL) { *outCalloutId = calloutId; }
    if (ctx->NumCallouts < KND_MAX_CALLOUTS) {
        ctx->CalloutIds[ctx->NumCallouts++] = calloutId;
    }

    RtlZeroMemory(&mCallout, sizeof(mCallout));
    mCallout.calloutKey = *key;
    mCallout.displayData.name = (wchar_t*)name;
    mCallout.applicableLayer = *layerKey;
    status = FwpmCalloutAdd0(ctx->EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(&filter, sizeof(filter));
    filter.layerKey = *layerKey;
    filter.displayData.name = (wchar_t*)name;
    filter.action.type = actionType;   /* INSPECTION for ALE, TERMINATING for STREAM */
    filter.action.calloutKey = *key;
    filter.subLayerKey = KND_SUBLAYER_GUID;
    filter.weight.type = FWP_EMPTY;       /* auto weight */
    filter.numFilterConditions = 0;        /* all traffic */
    return FwpmFilterAdd0(ctx->EngineHandle, &filter, NULL, NULL);
}

NTSTATUS
KndWfpStart(_Inout_ PKND_DEVICE_CONTEXT ctx)
{
    NTSTATUS status;
    FWPM_SUBLAYER0 sublayer;
    BOOLEAN inTx = FALSE;

    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &ctx->EngineHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Redirect handle for the transparent connect-redirect (non-fatal if it fails). */
    if (NT_SUCCESS(FwpsRedirectHandleCreate0(&KND_REDIRECT_PROVIDER, 0, &ctx->RedirectHandle))) {
        ctx->RedirectHandleCreated = TRUE;
    }

    status = FwpmTransactionBegin0(ctx->EngineHandle, 0);
    if (!NT_SUCCESS(status)) {
        goto fail;
    }
    inTx = TRUE;

    RtlZeroMemory(&sublayer, sizeof(sublayer));
    sublayer.subLayerKey = KND_SUBLAYER_GUID;
    sublayer.displayData.name = L"knd capture sublayer";
    sublayer.weight = 0x8000;
    status = FwpmSubLayerAdd0(ctx->EngineHandle, &sublayer, NULL);
    if (!NT_SUCCESS(status)) {
        goto fail;
    }
    ctx->SublayerAdded = TRUE;

    /* ALE flow-established: pure inspection (we never make a filtering decision). */
    status = KndRegisterCallout(ctx, &KND_CO_FLOW_V4, KndClassifyFlow,
                                L"knd flow v4", &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
                                FWP_ACTION_CALLOUT_INSPECTION, NULL, 0, NULL);
    if (!NT_SUCCESS(status)) { goto fail; }
    status = KndRegisterCallout(ctx, &KND_CO_FLOW_V6, KndClassifyFlow,
                                L"knd flow v6", &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,
                                FWP_ACTION_CALLOUT_INSPECTION, NULL, 0, NULL);
    if (!NT_SUCCESS(status)) { goto fail; }
    /* STREAM: terminating (so it can PERMIT + set a stream action) and
     * conditional-on-flow with a flow-delete notify. The flow-established callout
     * associates context per connection, which is what drives these to fire. */
    status = KndRegisterCallout(ctx, &KND_CO_STREAM_V4, KndClassifyStream,
                                L"knd stream v4", &FWPM_LAYER_STREAM_V4,
                                FWP_ACTION_CALLOUT_TERMINATING, KndFlowDelete,
                                FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW, &g_streamIdV4);
    if (!NT_SUCCESS(status)) { goto fail; }
    status = KndRegisterCallout(ctx, &KND_CO_STREAM_V6, KndClassifyStream,
                                L"knd stream v6", &FWPM_LAYER_STREAM_V6,
                                FWP_ACTION_CALLOUT_TERMINATING, KndFlowDelete,
                                FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW, &g_streamIdV6);
    if (!NT_SUCCESS(status)) { goto fail; }

    /* ALE connect-redirect (v4): transparent redirect to the local proxy. */
    status = KndRegisterCallout(ctx, &KND_CO_REDIRECT_V4, KndClassifyConnectRedirect,
                                L"knd redirect v4", &FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
                                FWP_ACTION_CALLOUT_TERMINATING, NULL, 0, NULL);
    if (!NT_SUCCESS(status)) { goto fail; }

    status = FwpmTransactionCommit0(ctx->EngineHandle);
    if (!NT_SUCCESS(status)) {
        goto fail;
    }
    ctx->CalloutsRegistered = TRUE;
    return STATUS_SUCCESS;

fail:
    if (inTx) {
        FwpmTransactionAbort0(ctx->EngineHandle);
    }
    KndWfpStop(ctx);
    return status;
}

VOID
KndWfpStop(_Inout_ PKND_DEVICE_CONTEXT ctx)
{
    UINT32 i;

    if (ctx->EngineHandle != NULL) {
        /* removing the engine handle drops the sublayer/callouts/filters we added */
        FwpmEngineClose0(ctx->EngineHandle);
        ctx->EngineHandle = NULL;
    }
    /* Unregister can return STATUS_DEVICE_BUSY while classify/flow-delete callbacks
     * are still draining; spin briefly so we never free the pool with a live callout. */
    for (i = 0; i < ctx->NumCallouts; ++i) {
        NTSTATUS s;
        ULONG tries = 0;
        do {
            s = FwpsCalloutUnregisterById0(ctx->CalloutIds[i]);
            if (s == STATUS_DEVICE_BUSY) {
                LARGE_INTEGER delay;
                delay.QuadPart = -(LONGLONG)(20 * 10 * 1000); /* 20 ms relative */
                KeDelayExecutionThread(KernelMode, FALSE, &delay);
            }
        } while (s == STATUS_DEVICE_BUSY && ++tries < 250);   /* ~5 s cap */
    }
    ctx->NumCallouts = 0;
    g_streamIdV4 = 0;
    g_streamIdV6 = 0;
    if (ctx->RedirectHandleCreated) {
        FwpsRedirectHandleDestroy0(ctx->RedirectHandle);
        ctx->RedirectHandleCreated = FALSE;
    }
    ctx->SublayerAdded = FALSE;
    ctx->CalloutsRegistered = FALSE;
}
