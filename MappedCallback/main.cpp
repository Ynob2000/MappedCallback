#include "internals.h"
#include "mapped_callback.h"

EXTERN_C NTSTATUS DriverEntry()
{
	if (!callback::findCodeCaves())
	{
		DbgPrint("Unable to find code caves in ntoskrnl");
		return STATUS_UNSUCCESSFUL;
	}
	
	if (!callback::alterFlags())
	{
		DbgPrint("Unable to alter flags");
		return STATUS_UNSUCCESSFUL;
	}

	if (!callback::applyTrampolines())
	{
		DbgPrint("Unable to apply trampoline to code caves");
		return STATUS_UNSUCCESSFUL;
	}
	
	if (!callback::startThread())
	{
		DbgPrint("Unable to start thread");
		return STATUS_UNSUCCESSFUL;
	}
	
	return STATUS_SUCCESS;

}