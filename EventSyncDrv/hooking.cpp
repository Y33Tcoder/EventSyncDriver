#include "hooking.h"
#include "utilities.h"
#include "comms.h"
BYTE original[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; //global byte array to store original syscall that will be hooked, so that it can be restored

#define UM_EXENAME L"umctrlproc.exe" //Usermode control process name to connect with this driver to enable arbitrary r/w on another um process
                                    //Note: this is NOT the target process!


HANDLE um_pid = NULL;   //um process pid
ULONG64 um_base64 = NULL;
PVOID* gafAsyncKeyState = NULL;

//========================global event variables
PKEVENT sync_event;
HANDLE event_handle;
PKEVENT sync_event2;
HANDLE event_handle2;
//========================
DWORD64 g_buffer_addr = NULL;

bool basichook::call_kernel_function(void* kernel_func_addr)
{
	if (!kernel_func_addr) { //exit if kernel func's addr is null
		return false;
	}

	log("hookhandler addr : %p", kernel_func_addr);

	PVOID* function = reinterpret_cast<PVOID*>(get_system_module_export("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", "NtQueryCompositionSurfaceStatistics"));

	if (!function) {
		return false;
	}
	
	BYTE dummy[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	

	BYTE shell_code[] = {0x48, 0xB8}; //mov rax, xxx (xxx is the base addr of our own func)
	BYTE shell_code_end[] = { 0xFF, 0xE0 }; //jmp rax


	//setup shellcode
	RtlSecureZeroMemory(&dummy, sizeof(dummy)); //zeros out dummy ptr's memory
	RtlSecureZeroMemory(&original, sizeof(original)); //zeros out original ptr's memory

	memcpy((PVOID)((ULONG_PTR)original), function, sizeof(original)); //copy original bytes into buffer

	memcpy((PVOID)((ULONG_PTR)dummy), &shell_code, sizeof(shell_code)); //copy front 2 bytes of shell code to dummy
	uintptr_t hook_addr = reinterpret_cast<uintptr_t>(kernel_func_addr); //get mapped driver handler base addr
	log("hookhandler addr after putting in dummy : %p", hook_addr);
	memcpy((PVOID)((ULONG_PTR)dummy + sizeof(shell_code)), &hook_addr, sizeof(void*)); //put mapped driver handler func addr into dummy
	memcpy((PVOID)((ULONG_PTR)dummy + sizeof(shell_code) + sizeof(void*)), &shell_code_end, sizeof(shell_code_end)); //put last 2 bytes of shell code into dummy

	
	
	for (int i = 0; i < sizeof(original)/sizeof(BYTE); i++)
	{
		log("%02X", original[i]); //for checking if original bytes are correct
	}
	

	//actually writing hook to overwrite original kernel func

	write_to_read_only_memory(function, &dummy, sizeof(dummy)); //write dummy into kernel func's (NtQueryXXXX) base addr

	//from this point on calling NtQueryCompositionSurfaceStatistics will direct to our own mapped driver handler instead
	return true;





}

bool basichook::unhook_kernel_function() {

	PVOID* function = reinterpret_cast<PVOID*>(get_system_module_export("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", "NtQueryCompositionSurfaceStatistics"));
	if (!function) {
		return false;
	}
	write_to_read_only_memory(function, &original, sizeof(original)); //write back original bytes into kernel func's (NtQueryXXXX) base addr

	return true;
}




// main driver start
VOID basichook::hook_handler(PVOID called_param1)
{
	//um control process rw buffer is stored in called_param1
	g_buffer_addr = *(DWORD64*)called_param1;
	
	

	
	log("buf addr: %llx", g_buffer_addr);
	


	
	
	basichook::unhook_kernel_function();
	log("unhooked!");
	
	////////////////////////////////////////////////unhoooked ntoskrnl.exe from here=================================
	//Create notification events for synchronization
	
	UNICODE_STRING event_name;
	UNICODE_STRING event_name2;
	RtlInitUnicodeString(&event_name, L"\\BaseNamedObjects\\Evnt1");
	RtlInitUnicodeString(&event_name2, L"\\BaseNamedObjects\\Evnt2");
	sync_event = IoCreateNotificationEvent(&event_name, &event_handle);
	sync_event2 = IoCreateNotificationEvent(&event_name2, &event_handle2);
	KeClearEvent(sync_event);
	KeClearEvent(sync_event2);


	
	//obtain um proc info
	um_pid = get_module_pid(UM_EXENAME);
	if (um_pid == NULL) {
		log("cant find pid of um control process! exiting km thread.");
		return;
	}

	//get process struct
	PEPROCESS um_process;
	if (PsLookupProcessByProcessId(um_pid, &um_process) != STATUS_SUCCESS) {
		return;
	}

	UNICODE_STRING um_name;
	RtlInitUnicodeString(&um_name, UM_EXENAME);
	um_base64 = get_module_base_x64(um_process, um_name);
	log("um control base addr: %llx", um_base64);

	//continuously wait for job from UM control proc
	while (comms::read_shared_buf()) {

	}
	return;

	ZwClose(um_pid);
	ZwClose(event_handle);
	ZwClose(event_handle2);

	
	
}