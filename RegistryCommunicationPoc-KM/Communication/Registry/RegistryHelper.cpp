#include <ntifs.h>
#include "../Controls.h"
#include "RegistryHelper.h"
#include "../CookieManager.h"

#pragma warning(disable: 6011 6387)

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

    NTSTATUS Status = STATUS_SUCCESS;
    REG_NOTIFY_CLASS Operation = REG_NOTIFY_CLASS(ULONG_PTR(Argument1));

    if (RegNtPreSetValueKey == Operation)
    {
        // Ensure its the correct registry path first
        PREG_OPEN_KEY_INFORMATION CallbackData = PREG_OPEN_KEY_INFORMATION(Argument2);

        PUNICODE_STRING pLocalCompleteName = NULL;
        if (CallbackData->CompleteName->Length > 0 && *CallbackData->CompleteName->Buffer != OBJ_NAME_PATH_SEPARATOR)
        {
            PCUNICODE_STRING pRootObjectName;
            Status = CmCallbackGetKeyObjectID(&g_CmCookie, CallbackData->RootObject, NULL, &pRootObjectName);

            if (NT_SUCCESS(Status))
            {
                //	Build the new name
                USHORT cbBuffer = pRootObjectName->Length;
                cbBuffer += sizeof(wchar_t);
                cbBuffer += CallbackData->CompleteName->Length;
                ULONG cbUString = sizeof(UNICODE_STRING) + cbBuffer;

                pLocalCompleteName = (PUNICODE_STRING)ExAllocatePoolWithTag(PagedPool, cbUString, 'tlFR');
                if (pLocalCompleteName)
                {
                    pLocalCompleteName->Length = 0;
                    pLocalCompleteName->MaximumLength = cbBuffer;
                    pLocalCompleteName->Buffer = (PWCH)((PCCH)pLocalCompleteName + sizeof(UNICODE_STRING));

                    RtlCopyUnicodeString(pLocalCompleteName, pRootObjectName);
                    RtlAppendUnicodeToString(pLocalCompleteName, L"\\");
                    RtlAppendUnicodeStringToString(pLocalCompleteName, CallbackData->CompleteName);
                }

                DbgPrint("[ FLARE ]: PreOpenKeyEx for %wZ\n", pLocalCompleteName ? pLocalCompleteName : CallbackData->CompleteName);

                PUNICODE_STRING pKeyNameBeingOpened = pLocalCompleteName ? pLocalCompleteName : CallbackData->CompleteName;

                //	Prevent callers from opening our secret registry key
                UNICODE_STRING TestKeyName;
                RtlInitUnicodeString(&TestKeyName, RegistryComunicationPath);
                if (RtlCompareUnicodeString(pKeyNameBeingOpened, &TestKeyName, TRUE))
                {
                    KdPrint(("[ FLARE ]: PreOpenKeyEx for %wZ being monitored!\n", pKeyNameBeingOpened));

                    PREG_SET_VALUE_KEY_INFORMATION PreSetValueInfo = PREG_SET_VALUE_KEY_INFORMATION(Argument2);
                    KPROCESSOR_MODE Mode = KernelMode;

                    Mode = ExGetPreviousMode();

                    if (UserMode == Mode)
                    {
                        Status = CaptureBuffer(
                            &RegOutData,
                            PreSetValueInfo->Data,
                            PreSetValueInfo->DataSize,
                            REGFLTR_CAPTURE_POOL_TAG
                        );
                    }
                    else
                    {
                        RegOutData = PreSetValueInfo->Data;
                    }
                }
            }
            else
            {
                goto LExit;
            }
        }

    LExit:
        if (pLocalCompleteName)
        {
            ExFreePool(pLocalCompleteName);
        }
    }

    return Status;
}