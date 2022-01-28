#include <ntifs.h>
#include "../Controls.h"
#include "RegistryHelper.h"

#pragma warning(disable: 6011 6387)

auto RegistryHelper::RegistryQueryValue(
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
                        pRegistryInformation->KeyValueResultBuffer,
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