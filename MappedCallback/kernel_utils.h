#pragma once

#include "internals.h"

namespace utils
{
	PVOID kernelBase = NULL;

	NTSTATUS writeToReadOnly(PVOID address, PVOID buffer, SIZE_T size, BOOLEAN reset = false)
	{
		auto mdl = IoAllocateMdl(address, (ULONG)size, FALSE, FALSE, NULL);
		if (!mdl)
			return STATUS_UNSUCCESSFUL;

		MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
		MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);

		auto mmMap = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
		RtlCopyMemory(mmMap, buffer, size);

		if (reset)
			MmProtectMdlSystemAddress(mdl, PAGE_READONLY);

		MmUnmapLockedPages(mmMap, mdl);
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);

		return STATUS_SUCCESS;
	}

	BOOLEAN writeTrampoline(PVOID address, PVOID target)
	{
		UCHAR trampoline[12] = {
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, xxxxxxxx
			0xFF, 0xE0                                                   // jmp rax
		};
		*(PVOID*)(trampoline + 2) = target;

		return NT_SUCCESS(writeToReadOnly(address, trampoline, 12, FALSE));
	}

	BOOLEAN removeTrampoline(PVOID address)
	{
		UCHAR trampoline[12] = {
			0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
			0xCC, 0xCC
		};

		return NT_SUCCESS(writeToReadOnly(address, trampoline, 12, TRUE));
	}

	PVOID getSystemModuleBase(PCCHAR module_name)
	{
		ULONG bytes = 0;
		PVOID moduleBase = NULL;

		// First fetch to retrieve the size
		ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
		if (!bytes)
			return moduleBase;

		// Allocate the size
		PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 'pool');
		if (!modules)
			return moduleBase;

		RtlZeroMemory(modules, bytes);

		// Fetch real data
		if (NT_SUCCESS(ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes)))
		{
			// Walk loaded modules
			PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
			for (ULONG i(0); i < modules->NumberOfModules; i++)
			{
				if (strstr((PCHAR)module[i].FullPathName, module_name) != NULL)
				{
					moduleBase = module[i].ImageBase;
					break;
				}
			}
		}

		ExFreePoolWithTag(modules, 'pool');
		return moduleBase;
	}

	PVOID getKernelBase()
	{
		if (kernelBase == NULL)
			return (kernelBase = getSystemModuleBase("ntoskrnl"));
		return kernelBase;
	}
}