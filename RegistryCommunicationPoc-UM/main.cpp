#include <Windows.h>
#include <stdio.h>
#include <string>

using namespace std;

typedef struct _CONTROL_VIRTUAL_MEMORY_ACTION_INFORMATION
{
	UINT32  TargetProcessId;
	UINT32  CommunicationControlId;
	DWORD64 DwControlActionAddress;
	SIZE_T  DwControlActionSize;
	DWORD64 DwOptionalNewProtection;
	DWORD64 DwOutOptionalOldProtection;
	DWORD64 DwOutResultStatus;
	DWORD64 DwOutResultValue;
} CONTROL_VIRTUAL_MEMORY_ACTION_INFORMATION, * PCONTROL_VIRTUAL_MEMORY_ACTION_INFORMATION;

LSTATUS SetRegistryValue(const wchar_t* KeyPath, const wchar_t* KeyValueName, PVOID data)
{
	HKEY hKey;
	LSTATUS Status = ERROR_SUCCESS;

	Status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, KeyPath, NULL, KEY_WRITE, &hKey);

	if (Status == ERROR_SUCCESS && hKey != NULL)
	{
		Status = RegSetValueExW(hKey, KeyValueName, NULL, REG_QWORD, (PBYTE)data, sizeof(data));
		RegCloseKey(hKey);
	}

	return Status;
}

int main()
{
	// Set Current Process ProcId as Kernel's Target ( This is not action process target!!! Its just needed to read the struct pointer! Call this once per usermode start session)

	DWORD64 KernelTargetProcId = GetCurrentProcessId();

	if (ERROR_SUCCESS == SetRegistryValue(L"Software\\KDCom", L"UmTargetProcId", &KernelTargetProcId))
		printf_s("Successfully set registry KernelTargetProcId value\n");

	// Set Data

	CONTROL_VIRTUAL_MEMORY_ACTION_INFORMATION controlVirtualMemoryActionInformation = CONTROL_VIRTUAL_MEMORY_ACTION_INFORMATION{};
	controlVirtualMemoryActionInformation.CommunicationControlId = 1230;

	PVOID pControlVirtualMemoryActionInformation = &controlVirtualMemoryActionInformation;

	if (ERROR_SUCCESS == SetRegistryValue(L"Software\\KDCom", L"ComStructAddress", &pControlVirtualMemoryActionInformation))
		printf_s("Successfully set registry ComStructAddress value\n");

	printf_s("pid -> %I64u\n", KernelTargetProcId);
	printf_s("ptr -> %p\n", &controlVirtualMemoryActionInformation);

	int _ = getchar();
}