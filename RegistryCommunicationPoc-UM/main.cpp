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

LSTATUS SetRegistryValue(PVOID data)
{
	HKEY hKey;
	LSTATUS Status = ERROR_SUCCESS;

	printf_s("ptr -> %p\n", data);

	Status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\KDCom", NULL, KEY_WRITE, &hKey);

	if (Status == ERROR_SUCCESS && hKey != NULL)
	{
		printf_s("check\n");
		Status = RegSetValueExW(hKey, L"ComStructAddress", NULL, REG_QWORD, (PBYTE)data, sizeof(data));
		RegCloseKey(hKey);
	}

	return Status;
}

int main()
{
	CONTROL_VIRTUAL_MEMORY_ACTION_INFORMATION controlVirtualMemoryActionInformation = CONTROL_VIRTUAL_MEMORY_ACTION_INFORMATION{};
	controlVirtualMemoryActionInformation.CommunicationControlId = 1230;

	if (ERROR_SUCCESS == SetRegistryValue(&controlVirtualMemoryActionInformation))
		printf_s("Success\n");

	printf_s("ptr -> %p\n", &controlVirtualMemoryActionInformation);

	getchar();
}