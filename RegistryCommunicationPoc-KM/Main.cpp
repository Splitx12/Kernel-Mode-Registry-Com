#include <ntifs.h>
#include "Communication/Controls.h"
#include "Communication/Registry/RegistryHelper.h"
#include "Communication/Memory/ActionManager.h"

#pragma warning(disable: 6001 6011 6387)

#define RegistryComunicationPath L"Computer\\HKEY_LOCAL_MACHINE\\SOFTWARE\\KDCom"

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS Status = STATUS_SUCCESS;

    UNICODE_STRING pUnicodeRegistryKeyFullPath;
    UNICODE_STRING pUnicodeRegistryKeyValueName;

    RtlInitUnicodeString(&pUnicodeRegistryKeyFullPath, RegistryComunicationPath);
    RtlInitUnicodeString(&pUnicodeRegistryKeyValueName, L"ComStructAddress");

    RegistryHelper* pRegistryHelper = new RegistryHelper();
    
    PVOID pKeyValueResultBuffer;
    REGISTRY_INFORMATION RegistryInformation = REGISTRY_INFORMATION{
        &pUnicodeRegistryKeyFullPath,
        &pUnicodeRegistryKeyValueName,
        REG_QWORD,
        MAX_KEY_SIZE,
        pKeyValueResultBuffer
    };

    //MemoryActionManager

    pRegistryHelper->RegistryQueryValue(&RegistryInformation);
    
    PCONTROL_VIRTUAL_MEMORY_ACTION_INFORMATION controlVirtualMemoryActionInformation =
        PCONTROL_VIRTUAL_MEMORY_ACTION_INFORMATION(
            ULONG_PTR(RegistryInformation.pKeyValueResultBuffer));
    
    Status = MemoryActionManager(controlVirtualMemoryActionInformation);

    return Status;
}