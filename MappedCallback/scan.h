#pragma once

#include "internals.h"

namespace scan
{
	UINT64 scanPattern(PUINT8 base, SIZE_T size, PCUCHAR pattern, PCUCHAR mask, SIZE_T patternSize) {
		for (SIZE_T i(0); i < size - patternSize; i++)
		{
			for (SIZE_T j(0); j < patternSize; j++)
			{
				if ((mask == NULL || mask[j] != '?') && *(PUINT8)(base + i + j) != (UINT8)(pattern[j]))
					break;

				if (j == patternSize - 1)
					return (UINT64)(base)+i;
			}
		}

		return NULL;
	}

	PVOID signatureScanBySection(PVOID baseAddress, PCCHAR sectionName, PCUCHAR pattern, PCUCHAR mask, SIZE_T len, PVOID start)
	{
		if (baseAddress == NULL)
			return NULL;

		PIMAGE_NT_HEADERS64 header = RtlImageNtHeader(baseAddress);
		if (!header)
			return NULL;

		ANSI_STRING ansiSectionName, ansiCurrentSectionName;
		RtlInitAnsiString(&ansiSectionName, sectionName);

		PIMAGE_SECTION_HEADER firstSection = (PIMAGE_SECTION_HEADER)((uintptr_t)&header->FileHeader + header->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER));

		// There can be multiple sections with the same name
		for (PIMAGE_SECTION_HEADER section(firstSection); section < firstSection + header->FileHeader.NumberOfSections; section++)
		{
			RtlInitAnsiString(&ansiCurrentSectionName, (PCCHAR)section->Name);
			if (!RtlCompareString(&ansiSectionName, &ansiCurrentSectionName, FALSE))
			{
				UINT64 result = scanPattern(start ? (PUINT8)start : ((PUINT8)baseAddress + section->VirtualAddress), section->Misc.VirtualSize, pattern, mask, len);
				if (result != NULL)
					return (PVOID)result;
			}
		}

		return NULL;
	}

	PVOID findCodeCave(PVOID baseAddress, PCUCHAR pattern, SIZE_T len, PVOID start)
	{
		PCUCHAR mask = (PCUCHAR)ExAllocatePool(PagedPool, len);
		RtlFillMemory((PVOID)mask, len, 'x');
		PVOID codeCave = signatureScanBySection(baseAddress, ".text", pattern, mask, len, start);
		ExFreePool((PVOID)mask);
		return codeCave;
	}
}
