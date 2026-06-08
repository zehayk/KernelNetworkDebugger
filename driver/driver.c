/*
 * driver.c - DriverEntry, control device, dispatch wiring, unload.
 *
 * The device is created with IoCreateDeviceSecure and an admin-only ACL: only
 * SYSTEM and the local Administrators group may open it. This is deliberate,
 * because the device exposes the (scoped) phys R/W IOCTL; we do not want an
 * unprivileged caller poking at it.
 */

#include "knd_driver.h"
#include <wdmsec.h>   /* IoCreateDeviceSecure; link wdmsec.lib */

PKND_DEVICE_CONTEXT g_Knd = NULL;

/* Allow GENERIC_ALL to SYSTEM (SY) and Built-in Administrators (BA) only. */
static const UNICODE_STRING g_KndSddl =
    RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

/* {6F1A3C2F-9E44-4B0E-9C2A-3D7F1B2E5AFF} - device class for IoCreateDeviceSecure */
static const GUID KND_DEVCLASS_GUID =
    { 0x6f1a3c2f, 0x9e44, 0x4b0e, { 0x9c, 0x2a, 0x3d, 0x7f, 0x1b, 0x2e, 0x5a, 0xff } };

DRIVER_UNLOAD KndUnload;
DRIVER_INITIALIZE DriverEntry;

VOID
KndUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symlink;
    PKND_DEVICE_CONTEXT ctx = g_Knd;

    UNREFERENCED_PARAMETER(DriverObject);

    if (ctx != NULL) {
        KndWfpStop(ctx);

        RtlInitUnicodeString(&symlink, KND_SYMLINK_NAME);
        IoDeleteSymbolicLink(&symlink);

        if (ctx->DeviceObject != NULL) {
            IoDeleteDevice(ctx->DeviceObject);
        }

        KndRingDestroy(ctx);

        g_Knd = NULL;
        ExFreePoolWithTag(ctx, KND_POOL_TAG);
    }
}

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symlink;
    PDEVICE_OBJECT deviceObject = NULL;
    PKND_DEVICE_CONTEXT ctx = NULL;
    BOOLEAN symlinkCreated = FALSE;

    UNREFERENCED_PARAMETER(RegistryPath);

    ctx = (PKND_DEVICE_CONTEXT)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*ctx), KND_POOL_TAG);
    if (ctx == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ExInitializeFastMutex(&ctx->MapLock);
    ctx->NextFlowId = 0;
    ctx->NextSequence = 0;
    ctx->CaptureActive = 0;

    /* Cache ring first so the device is fully usable the moment it appears. */
    status = KndRingCreate(ctx, KND_DEFAULT_RING_DATA_SIZE);
    if (!NT_SUCCESS(status)) {
        goto fail;
    }

    RtlInitUnicodeString(&deviceName, KND_DEVICE_NAME);
    status = IoCreateDeviceSecure(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN,
                                  FILE_DEVICE_SECURE_OPEN, FALSE,
                                  &g_KndSddl, &KND_DEVCLASS_GUID, &deviceObject);
    if (!NT_SUCCESS(status)) {
        goto fail;
    }
    ctx->DeviceObject = deviceObject;

    RtlInitUnicodeString(&symlink, KND_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symlink, &deviceName);
    if (!NT_SUCCESS(status)) {
        goto fail;
    }
    symlinkCreated = TRUE;

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = KndDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP]        = KndDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = KndDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = KndDispatchDeviceControl;
    DriverObject->DriverUnload = KndUnload;

    /* Publish the context before WFP callouts can fire. */
    g_Knd = ctx;

    /* Register WFP capture now; actual recording is gated by CaptureActive,
     * which starts at 0 until the app sends IOCTL_KND_START_CAPTURE. */
    status = KndWfpStart(ctx);
    if (!NT_SUCCESS(status)) {
        g_Knd = NULL;
        goto fail;
    }

    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;

fail:
    if (symlinkCreated) {
        IoDeleteSymbolicLink(&symlink);
    }
    if (deviceObject != NULL) {
        IoDeleteDevice(deviceObject);
    }
    KndRingDestroy(ctx);
    ExFreePoolWithTag(ctx, KND_POOL_TAG);
    return status;
}
