#pragma once

#include "Exports.h"
#include "..\Controls.h"

auto MemoryActionManager(
	PCONTROL_VIRTUAL_MEMORY_ACTION_INFORMATION pControlVirtualMemoryActionInfo
) -> NTSTATUS
{
	NTSTATUS Status{};
	PEPROCESS TargetProcess{};
	SIZE_T MmCopyVirtualMemoryReturnSize{};

	Status = PsLookupProcessByProcessId(HANDLE(pControlVirtualMemoryActionInfo->TargetProcessId), &TargetProcess);

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("[ FLARE ] Unable to find process id: %X\n", Status);

		return Status;
	}

	UINT32 ControlId = pControlVirtualMemoryActionInfo->CommunicationControlId;

	if (ControlActions(ControlId) == ControlActions::Write)
	{
		Status = MmCopyVirtualMemory
		(
			IoGetCurrentProcess(),
			PVOID(pControlVirtualMemoryActionInfo->DwOutResultValue),
			TargetProcess,
			PVOID(pControlVirtualMemoryActionInfo->DwControlActionAddress),
			pControlVirtualMemoryActionInfo->DwControlActionSize,
			UserMode,
			&MmCopyVirtualMemoryReturnSize
		);

		pControlVirtualMemoryActionInfo->DwOutResultStatus = Status;
	}
	else if (ControlActions(ControlId) == ControlActions::Read)
	{
		Status = MmCopyVirtualMemory(
			TargetProcess,
			PVOID(pControlVirtualMemoryActionInfo->DwControlActionAddress),
			IoGetCurrentProcess(),
			PVOID(pControlVirtualMemoryActionInfo->DwOutResultValue),
			pControlVirtualMemoryActionInfo->DwControlActionSize,
			UserMode,
			&MmCopyVirtualMemoryReturnSize
		);

		pControlVirtualMemoryActionInfo->DwOutResultStatus = Status;
	}

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("[ FLARE ] Unable to copy virtual memory: %x\n", Status);
		return Status;
	}

	ObfDereferenceObject(TargetProcess);

	return Status;
}
