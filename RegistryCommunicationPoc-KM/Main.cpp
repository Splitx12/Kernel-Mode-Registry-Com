/*
    Author: github.com/CycloneOrg

    TODO:
    add dynamic device name initialization throught registry values
    add dynamic registry key communicaiton path throught the same device name registry key
    comment the code in-depth
*/

#include <ntifs.h>
#include <ntstrsafe.h>
#include <wdmsec.h>

#include "Communication/Controls.h"
#include "Communication/Registry/RegistryHelper.h"
#include "Communication/Memory/ActionManager.h"
#include "Communication/CookieManager.h"

#pragma warning(disable: 6001 6011 6387)

auto DriverUnload(
    IN PDRIVER_OBJECT pDriverObject
) -> VOID
{
    UNREFERENCED_PARAMETER(pDriverObject);
    PAGED_CODE();

    NTSTATUS Status = CmUnRegisterCallback(g_CmCookie);
    if (!NT_SUCCESS(Status))
    {
        DbgPrint("[ FLARE ] Failed to unregister... what to do now, sir?");
    }
}

#define MIN_ALTITUDE 360000
#define MAX_ALTITUDE 389999

auto DriverEntry(
    PDRIVER_OBJECT pDriverObject,
    PUNICODE_STRING pRegistryPath
) -> NTSTATUS
{
    UNREFERENCED_PARAMETER(pRegistryPath);

    // Set Driver Unload Function
    pDriverObject->DriverUnload = DriverUnload;

    NTSTATUS Status = STATUS_SUCCESS;

    // Full path to the registry's key
    UNICODE_STRING pUnicodeRegistryKeyFullPath;
    // Name for the registry's key vale
    UNICODE_STRING pUnicodeRegistryKeyValueName;

    RtlInitUnicodeString(&pUnicodeRegistryKeyFullPath, RegistryComunicationPath);
    RtlInitUnicodeString(&pUnicodeRegistryKeyValueName, L"ComStructAddress");

    PVOID pKeyValueResultBuffer = NULL;
    RegistryInformation = REGISTRY_INFORMATION{
        &pUnicodeRegistryKeyFullPath,
        &pUnicodeRegistryKeyValueName,
        REG_QWORD,
        MAX_KEY_SIZE,
        pKeyValueResultBuffer
    };

    UNICODE_STRING AltitudeString = RTL_CONSTANT_STRING(L"360000");
    
    ULONG ulAltitudeStart = MIN_ALTITUDE;

    NewAttitudeRetry:
    Status = CmRegisterCallbackEx
    (
        RegFilterRegistryCallback,
        &AltitudeString,
        pDriverObject,
        NULL,
        &g_CmCookie,
        NULL
    );

    while (Status == STATUS_FLT_INSTANCE_ALTITUDE_COLLISION && ulAltitudeStart >= MIN_ALTITUDE && ulAltitudeStart <= MAX_ALTITUDE)
    {
        ulAltitudeStart++;

        RtlIntegerToUnicodeString(ulAltitudeStart, NULL, &AltitudeString);

        goto NewAttitudeRetry;
    }

    if (!NT_SUCCESS(Status))
    {
        if (Status == STATUS_FLT_INSTANCE_ALTITUDE_COLLISION)
            DbgPrint("[ FLARE ] Altitude collision");
        else if (Status == STATUS_INSUFFICIENT_RESOURCES)
            DbgPrint("[ FLARE ] Failed to allocate memory");
        else
            DbgPrint("[ FLARE ] Failed to register");
    }

    DbgPrint("[ FLARE ] Exiting");

    return Status;
}