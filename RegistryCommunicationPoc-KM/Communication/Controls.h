#pragma once

// .. Data Wrapper

#define MAX_KEY_SIZE 8

enum struct ControlActions
{
	Read     = 0,
	Write    = 1,
	Protect  = 2,
	Allocate = 3,
	Free     = 4
};

typedef struct _REGISTRY_INFORMATION
{
	IN  PUNICODE_STRING pUnicodeRegistryKeyFullPath;
	IN  PUNICODE_STRING pUnicodeRegistryKeyValueName;
	IN  ULONG           KeyValueType;
	IN  UINT32          KeyValueDataMaxLenght;
	OUT PVOID           pKeyValueResultBuffer;
} REGISTRY_INFORMATION, *PREGISTRY_INFORMATION;

// .. Action Control

typedef struct _CONTROL_VIRTUAL_MEMORY_ACTION_INFORMATION
{
	IN  UINT32  TargetProcessId;
	IN  UINT32  CommunicationControlId;
	IN  DWORD64 DwControlActionAddress;
	IN  SIZE_T  DwControlActionSize;
	IN  DWORD64 DwOptionalNewProtection;
	OUT DWORD64 DwOutOptionalOldProtection;
	OUT DWORD64 DwOutResultStatus;
	OUT DWORD64 DwOutResultValue;
} CONTROL_VIRTUAL_MEMORY_ACTION_INFORMATION, *PCONTROL_VIRTUAL_MEMORY_ACTION_INFORMATION;