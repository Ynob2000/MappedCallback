#pragma once

#include "internals.h"
#include "kernel_utils.h"
#include "scan.h"

typedef LDR_DATA_TABLE_ENTRY* (*fnMiLookupDataTableEntry)(PVOID Address, BOOLEAN);
fnMiLookupDataTableEntry MiLookupDataTableEntry;
UCHAR fnPattern[18] = {	0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x70, 0x18, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x33, 0xF6 };

PVOID codeCaveThread = NULL;
PVOID codeCaveCallback = NULL;

namespace callback
{
	VOID callbackRoutine(PKPROCESS process, HANDLE handle, PPS_CREATE_NOTIFY_INFO createNotifyInfo)
	{
		UNREFERENCED_PARAMETER(createNotifyInfo);
		UNREFERENCED_PARAMETER(handle);
		DbgPrint("New process created: %s\n", ((EPROCESS*)process)->ImageFileName);
	}

	VOID callbackThread()
	{
		// Remove previous trampoline
		if (!utils::removeTrampoline(codeCaveThread))
			return;

		DbgPrint("Setup the callback\n");
		// Setup the callback
		PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)codeCaveCallback, FALSE);
	}

	BOOLEAN findCodeCaves()
	{
		// Start from ACPI base
		PVOID base = utils::getSystemModuleBase("ACPI");

		// Find a codecave for the thread
		UCHAR codeCave[12];
		RtlFillMemory(codeCave, 12, 0xCC);
		codeCaveThread = scan::findCodeCave(base, codeCave, 12, 0);
		if (!codeCaveThread)
		{
			DbgPrint("Unable to find codecave for thread");
			return FALSE;
		}

		// Find a codecave for the callback
		codeCaveCallback = scan::findCodeCave(base, codeCave, 12, (PUINT8)codeCaveThread + 12);
		if (!codeCaveCallback)
		{
			DbgPrint("Unable to find codecave for callback");
			return FALSE;
		}

		return TRUE;
	}

	BOOLEAN alterFlags()
	{
		// Avoid BSOD by tinkering with the Flags attribute for the corresponding data table entry
		UCHAR mask[18];
		RtlFillMemory(mask, 18, 'x');
		MiLookupDataTableEntry = (fnMiLookupDataTableEntry)scan::signatureScanBySection(utils::getKernelBase(), ".text", fnPattern, mask, 18, 0);
		if (!MiLookupDataTableEntry)
			return FALSE;

		LDR_DATA_TABLE_ENTRY* ldr = MiLookupDataTableEntry(codeCaveCallback, FALSE);
		if (!ldr)
			return FALSE;

		ldr->Flags |= 0x20;
		return TRUE;
	}

	BOOLEAN applyTrampolines()
	{
		if (!utils::writeTrampoline(codeCaveThread, &callbackThread))
			return FALSE;

		if (!utils::writeTrampoline(codeCaveCallback, &callbackRoutine))
			return FALSE;

		return TRUE;
	}

	BOOLEAN startThread()
	{
		HANDLE handle;
		NTSTATUS status = PsCreateSystemThread(&handle, THREAD_ALL_ACCESS, 0, 0, 0, (KSTART_ROUTINE*)codeCaveThread, 0);

		return NT_SUCCESS(status);
	}
}