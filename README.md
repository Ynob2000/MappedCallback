# MappedCallback
Register a callback in Kernel from a manually mapped driver.

## Limitations
Registering a callback in the kernel without taking further precautions will either not work or lead to a nice BSOD. 
This small driver, designed to be manually mapped, is able to register a callback in the kernel without triggering any crash.

## How?
By finding a codecave in a legit module in the kernel, we can write a JMP to our routines so that the start address of the registered function for the callback is in a valid module.<br/>
On top of that, we need to find a way to circumvent MmVerifyCallbackFunction, which is a routine designed to check for the presence of unwanted callbacks.<br/>
If we take a look at this function, we see that it's just a call to MmVerifyCallbackFunctionCheckFlags, with arg = 0x20<br/>
![Alt Text](/img/MmVerifyCallbackFunction.png)<br/>
Then we have a look at MmVerifyCallbackFunctionCheckFlags<br/>
![Alt Text](/img/MmVerifyCallbackFunctionCheckFlags.png)<br/>
The 0x68 here corresponds to the offset of attribute Flags for struct _LDR_DATA_TABLE_ENTRY, as defined in internals.h
So all we need to do, is find the corresponding data table entry and change the flag so the function will not crash the OS.<br/>
Unfortunately, the MiLookupDataTableEntry function is not exported by ntoskrnl, so we need to make a signature of this function and find it ourselves in memory
