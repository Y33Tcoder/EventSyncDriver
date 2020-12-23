#include "hooking.h"
#include "utilities.h"

//NOTE: This driver is intended to be manual mapped with kdmapper (or other vulnerable driver manual mappers)
// kdmapper sources:
// - https://github.com/TheCruZ/kdmapper-1803-20H2
// - https://github.com/z175/kdmapper


extern "C" NTSTATUS MainEntry(PDRIVER_OBJECT, PUNICODE_STRING) {


	//since we are using kdmapper and manual mapping, no use for driver object

	
	Sleep(2000);

	basichook::call_kernel_function(&basichook::hook_handler); //passing the addr of the func that is to be executed (i.e. the main loop of driver)
	//hooks the kernel syscall in ntoskrnl.exe
	log("hook loaded!");

	return STATUS_SUCCESS;
}