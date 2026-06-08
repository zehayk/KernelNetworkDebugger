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
    if (FWPS_IS_METADATA_FIELD_PRESENT(inMeta, FWPS_METADATA_FIELD_FLOW_HANDLE)) {
        p.flowId = inMeta->flowHandle;
    } else {
        p.flowId = (ULONGLONG)KndNextFlowId(ctx);
    }

    KndFillProcessInfo(inMeta, &p);

    if (KndRingWrite(ctx, (USHORT)KND_REC_CONN_OPEN, 0, &p, sizeof(p), NULL, 0)) {
        InterlockedIncrement((volatile LONG*)&ctx->Ring->activeFlows);
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
    UNREFERENCED_PARAMETER(flowContext);

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

    flowId = FWPS_IS_METADATA_FIELD_PRESENT(inMeta, FWPS_METADATA_FIELD_FLOW_HANDLE)
                 ? inMeta->flowHandle : 0;

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
                   _In_ const GUID* layerKey, _In_ UINT32 actionType)
{
    FWPS_CALLOUT1 sCallout;
    FWPM_CALLOUT0 mCallout;
    FWPM_FILTER0 filter;
    UINT32 calloutId = 0;
    NTSTATUS status;

    RtlZeroMemory(&sCallout, sizeof(sCallout));
    sCallout.calloutKey = *key;
    sCallout.classifyFn = classifyFn;
    sCallout.notifyFn = KndNotifyFn;
    sCallout.flowDeleteFn = NULL;

    status = FwpsCalloutRegister1(ctx->DeviceObject, &sCallout, &calloutId);
    if (!NT_SUCCESS(status)) {
        return status;
    }
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
                                FWP_ACTION_CALLOUT_INSPECTION);
    if (!NT_SUCCESS(status)) { goto fail; }
    status = KndRegisterCallout(ctx, &KND_CO_FLOW_V6, KndClassifyFlow,
                                L"knd flow v6", &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,
                                FWP_ACTION_CALLOUT_INSPECTION);
    if (!NT_SUCCESS(status)) { goto fail; }
    /* STREAM: must be terminating to legally PERMIT + set a stream action, even
     * though we always permit unmodified. NOTE to confirm at first run: if the
     * stream callout never fires with data, the flow likely needs
     * FwpsFlowAssociateContext() called from KndClassifyFlow to enable stream
     * inspection on that flow. Verify with a DbgPrint at the top of each classify. */
    status = KndRegisterCallout(ctx, &KND_CO_STREAM_V4, KndClassifyStream,
                                L"knd stream v4", &FWPM_LAYER_STREAM_V4,
                                FWP_ACTION_CALLOUT_TERMINATING);
    if (!NT_SUCCESS(status)) { goto fail; }
    status = KndRegisterCallout(ctx, &KND_CO_STREAM_V6, KndClassifyStream,
                                L"knd stream v6", &FWPM_LAYER_STREAM_V6,
                                FWP_ACTION_CALLOUT_TERMINATING);
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
    for (i = 0; i < ctx->NumCallouts; ++i) {
        FwpsCalloutUnregisterById0(ctx->CalloutIds[i]);
    }
    ctx->NumCallouts = 0;
    ctx->SublayerAdded = FALSE;
    ctx->CalloutsRegistered = FALSE;
}
