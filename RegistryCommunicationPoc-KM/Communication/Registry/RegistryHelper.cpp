#include <ntifs.h>
#include <ntstrsafe.h>

#include "../Controls.h"
#include "RegistryHelper.h"
#include "../CookieManager.h"
#include "../Memory/Exports.h"

#pragma warning(disable: 6011 6001 6387)

ULONG ExceptionFilter(_In_ PEXCEPTION_POINTERS ExceptionPointers)
{

    DbgPrint("[ FLARE ] Exception %lx, ExceptionPointers = %p", ExceptionPointers->ExceptionRecord->ExceptionCode, ExceptionPointers);

    DbgBreakPoint();

    return EXCEPTION_EXECUTE_HANDLER;

}

auto RegistryQueryValue(
    PREGISTRY_INFORMATION pRegistryInformation
) -> NTSTATUS
{
    PKEY_VALUE_PARTIAL_INFORMATION pKeyValuePartialInfo{};
    ULONG keyValPartialInfoLenght, queryResultLen;
    OBJECT_ATTRIBUTES objectAttributes{};
    HANDLE hRegistryKey;
    NTSTATUS Status;

    Status = STATUS_SUCCESS;

    InitializeObjectAttributes(&objectAttributes, pRegistryInformation->pUnicodeRegistryKeyFullPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = ZwOpenKey(&hRegistryKey, KEY_QUERY_VALUE, &objectAttributes);

    if (!NT_SUCCESS(Status))
        return STATUS_FAIL_CHECK;

    keyValPartialInfoLenght = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + pRegistryInformation->KeyValueDataMaxLenght;

    pKeyValuePartialInfo = PKEY_VALUE_PARTIAL_INFORMATION(
        ExAllocatePool(NonPagedPool, keyValPartialInfoLenght)
    );

    Status = ZwQueryValueKey
    (
        hRegistryKey,
        pRegistryInformation->pUnicodeRegistryKeyValueName,
        KeyValuePartialInformation,
        pKeyValuePartialInfo,
        keyValPartialInfoLenght,
        &queryResultLen
    );

    if ((NT_SUCCESS(Status) || Status == STATUS_BUFFER_OVERFLOW))
    {
        if (queryResultLen >= (sizeof(KEY_VALUE_PARTIAL_INFORMATION) - 1))
        {
            if (!pRegistryInformation->KeyValueType || pKeyValuePartialInfo->Type == pRegistryInformation->KeyValueType)
            {
                __try
                {
                    queryResultLen = pKeyValuePartialInfo->DataLength;

                    memcpy
                    (
                        pRegistryInformation->pKeyValueResultBuffer,
                        pKeyValuePartialInfo->Data,
                        min(pRegistryInformation->KeyValueDataMaxLenght, queryResultLen)
                    );

                    Status = STATUS_SUCCESS;
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = STATUS_FAIL_CHECK;
                }
            }
        }
    }

    ExFreePoolWithTag(pKeyValuePartialInfo, NULL);

    ZwClose(hRegistryKey);

    return Status;
}

NTSTATUS
CaptureBuffer(
    _Outptr_result_maybenull_ PVOID* CapturedBuffer,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ SIZE_T Length,
    _In_ ULONG PoolTag
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PVOID TempBuffer = NULL;

    NT_ASSERT(CapturedBuffer != NULL);

    if (Length == 0) {
        *CapturedBuffer = NULL;
        return Status;
    }

    TempBuffer = (PCALLBACK_CONTEXT)ExAllocatePoolZero(
        PagedPool,
        Length,
        PoolTag);

    if (TempBuffer != NULL)
    {
        __try {
            RtlCopyMemory(TempBuffer, Buffer, Length);
        } __except(ExceptionFilter(GetExceptionInformation())) {
            DbgPrint("[ FLARE ] Capturing buffer failed with exception");
            ExFreePoolWithTag(TempBuffer, PoolTag);
            TempBuffer = NULL;
            Status = GetExceptionCode();
        }
    }
    else
    {
        DbgPrint("[ FLARE ] Capturing buffer failed wtih insufficient resources");
        Status = STATUS_INSUFFICIENT_RESOURCES;
    }

    *CapturedBuffer = TempBuffer;

    return Status;
}

auto RegFilterRegistryCallback(
    PVOID CallbackContext,
    PVOID Argument1,
    PVOID Argument2
) -> NTSTATUS
{
    UNREFERENCED_PARAMETER(CallbackContext);

    //DbgPrint("[ FLARE ] Filter Callback");

    NTSTATUS Status = STATUS_SUCCESS;
    REG_NOTIFY_CLASS Operation = REG_NOTIFY_CLASS(ULONG_PTR(Argument1));

    if (RegNtPreSetValueKey == Operation)
    {
        // Ensure its the correct registry path first
        PREG_SET_VALUE_KEY_INFORMATION pRegPreSetValueInfo = PREG_SET_VALUE_KEY_INFORMATION(Argument2);
        
        UNICODE_STRING StructComKeyValueName;
        RtlInitUnicodeString(&StructComKeyValueName, L"ComStructAddress");
        
        UNICODE_STRING UsermodeTargetProcIdKeyValueName;
        RtlInitUnicodeString(&StructComKeyValueName, L"UmTargetProcId");

        // DbgPrint("[ FLARE ] Unicode Reg Value Name -> %wZ", pRegPreSetValueInfo->ValueName);

        // Ensure string is zero terminated to avoid bsodding when encountering a non-zero terminated string with wcsstr
        
        if (NULL == RtlCompareUnicodeString(pRegPreSetValueInfo->ValueName, &UsermodeTargetProcIdKeyValueName, TRUE))
        {
            DbgPrint("[ FLARE ] Matched UmTargetProcId");

            PVOID LocalData = NULL;

            __try
            {
                Status = CaptureBuffer(
                    &LocalData,
                    pRegPreSetValueInfo->Data,
                    pRegPreSetValueInfo->DataSize,
                    REGFLTR_CAPTURE_POOL_TAG
                );

                DbgPrint("[ FLARE ] LocalData: %x", DWORD64(LocalData));

                if (NT_SUCCESS(Status) && LocalData != NULL)
                {
                    UmTargetProcId = DWORD64(LocalData);
                    TargetAcquired = TRUE;
                }
            }
            __except (ExceptionFilter(GetExceptionInformation()))
            {
                Status = GetExceptionCode();
                DbgPrint("[ FLARE ] Exception while capturing pid buffer, error code: %x", Status);
            }

            if (NULL != LocalData)
                ExFreePoolWithTag(LocalData, REGFLTR_CAPTURE_POOL_TAG);
        }
        //else if (NULL == RtlCompareUnicodeString(pRegPreSetValueInfo->ValueName, &StructComKeyValueName, TRUE) && TargetAcquired)
        //{
        //    KdPrint(("[ FLARE ]: PreOpenKeyEx for %wZ being monitored!\n", pRegPreSetValueInfo->ValueName));

        //    PVOID LocalData = NULL;

        //    __try
        //    {
        //        Status = CaptureBuffer(
        //            &LocalData,
        //            pRegPreSetValueInfo->Data,
        //            pRegPreSetValueInfo->DataSize,
        //            REGFLTR_CAPTURE_POOL_TAG
        //        );
        //    }
        //    __except (ExceptionFilter(GetExceptionInformation()))
        //    {
        //        Status = GetExceptionCode();
        //        DbgPrint("[ FLARE ] Exception while capturing buffer, error code: %x", Status);
        //    }

        //    RegOutData = LocalData;

        //    if (NT_SUCCESS(Status) && NULL != LocalData && RegPrevData != RegOutData)
        //    {
        //        RegistryQueryValue(&RegistryInformation);

        //        CONTROL_VIRTUAL_MEMORY_ACTION_INFORMATION ControlVirtualMemoryActionInformation { NULL };

        //        PEPROCESS PeProcess;
        //        PsLookupProcessByProcessId(HANDLE(UmTargetProcId), &PeProcess);

        //        __try
        //        {
        //            Status = MmCopyVirtualMemory(PeProcess, &ControlVirtualMemoryActionInformation, IoGetCurrentProcess(), RegistryInformation.pKeyValueResultBuffer, sizeof DWORD64, UserMode, NULL);
        //            if (!NT_SUCCESS(Status))
        //            {
        //                DbgPrint("[ FLARE ] Failed to read struct pointer, check your address");
        //                goto Cleanup;
        //            }
        //        }
        //        __except (ExceptionFilter(GetExceptionInformation()))
        //        {
        //            Status = GetExceptionCode();
        //            DbgPrint("[ FLARE ] Exception while reading com struct, error code: %x", Status);

        //            goto Cleanup;
        //        }

        //        DbgPrint("[ FLARE ] controlVirtualMemoryActionInformation->CommunicationControlId = %lu", ControlVirtualMemoryActionInformation.CommunicationControlId);
        //        
        //        RegPrevData = RegOutData;
        //        //Status = MemoryActionManager(controlVirtualMemoryActionInformation);
        //    }

        //    Cleanup:
        //    if (NULL != LocalData)
        //        ExFreePoolWithTag(LocalData, REGFLTR_CAPTURE_POOL_TAG);
        //}
    }

    return Status;
}