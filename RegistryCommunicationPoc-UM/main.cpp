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

#define RegistryComunicationPath L"SOFTWARE\\KDCom"

LSTATUS SetRegistryValue(HKEY key, wstring path, wstring value, PVOID data)
{
	HKEY hKey;
	LSTATUS Status = ERROR_SUCCESS;

	if (RegOpenKeyExW(key, path.c_str(), NULL, KEY_WRITE, &hKey) == ERROR_SUCCESS && hKey != NULL)
	{
		Status = RegSetValueExW(hKey, value.c_str(), NULL, REG_QWORD, (BYTE*)data, sizeof(data));
		RegCloseKey(hKey);
	}

	return Status;
}

int main()
{
	CONTROL_VIRTUAL_MEMORY_ACTION_INFORMATION controlVirtualMemoryActionInformation = CONTROL_VIRTUAL_MEMORY_ACTION_INFORMATION{};
	controlVirtualMemoryActionInformation.CommunicationControlId = 1230;

	if (ERROR_SUCCESS == SetRegistryValue(HKEY_LOCAL_MACHINE, RegistryComunicationPath, L"Address", (PVOID)&controlVirtualMemoryActionInformation))
		printf_s("Success");

	getchar();
}