#include "memory.h"

PVOID get_system_module_base(const char* module_name)
{
	ULONG bytes = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, NULL, bytes, &bytes); //ZwQuerySystemInformation params: infoclass, buffer, length, returnlength

	if (!bytes) {
		UNICODE_STRING string0 = RTL_CONSTANT_STRING(L"preliminary ZwQuerySysInfo failed!\n");
		DbgPrint("%zW", &string0);
		//RtlFreeUnicodeString(&string0);
		return NULL;
	} 

	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x4e554c4c); //Tag is NULL, allocates non-paged mem pool pointed to by pointer "modules"

	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes); //actually load modules info into status ptr

	if (!NT_SUCCESS(status)) {
		UNICODE_STRING string1 = RTL_CONSTANT_STRING(L"ExAllocatePoolWithTag failed, or ZwQuerySysInfo status is NULL!\n");
		DbgPrint("%zW", &string1);
		//RtlFreeUnicodeString(&string1);
		
		return NULL;
	}

	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
	PVOID module_base = 0, module_size = 0;

	for (ULONG i = 0; i < modules->NumberOfModules; ++i) {

		if (strcmp((char*)module[i].FullPathName, module_name) == 0) { //if path matches module
			module_base = module[i].ImageBase; //image base for addr calculation
			module_size = (PVOID)module[i].ImageSize;
			//log("found module base! %s %p", module_name, module_base);
			break;

		}
	}

	if (modules) {
		ExFreePoolWithTag(modules, NULL);
	}
	if (module_base <= NULL) {
		return NULL;
	}
	
	return module_base;

}


HANDLE get_module_pid(PCWSTR module_name)
{

	UNICODE_STRING WantedImageName;
	HANDLE found_pid = NULL;

	RtlInitUnicodeString(&WantedImageName, (PCWSTR)module_name);
	ULONG bytes = 0;
	PVOID buffer;
	NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, NULL, bytes, &bytes); //ZwQuerySystemInformation params: infoclass, buffer, length, returnlength

	if (!bytes) {
		log("ZwQuerySysInfo for PID failed!\n");
		return NULL;
	}
	//buffer saves original addr of mem pool for deletion
	buffer = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x4e554c4c); //Tag is NULL, allocates non-paged mem pool pointed to by pointer "modules"

	PSYSTEM_PROCESS_INFORMATION processes = (PSYSTEM_PROCESS_INFORMATION)buffer;

	status = ZwQuerySystemInformation(SystemProcessInformation, processes, bytes, &bytes); //actually load modules info into status ptr

	if (!NT_SUCCESS(status)) {
		log("ExAllocatePoolWithTag failed, or ZwQuerySysInfo status is NULL when finding PID!\n");
		return NULL;
	}
	
	for (;;) {
		//log("\nProcess name: %ws | Process ID: %d\n", processes->ImageName.Buffer, processes->UniqueProcessId); // Display process information.
		if (RtlEqualUnicodeString(&processes->ImageName, &WantedImageName, TRUE)) {
			log("%ws has been found!\n", processes->ImageName.Buffer);
			found_pid = processes->UniqueProcessId;
			break;
		}
		else if (processes->NextEntryOffset) {
			processes = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)processes + processes->NextEntryOffset);
		}
		else {
			
			break;
		}
	}
	
	
	
	ExFreePoolWithTag(buffer, NULL);
	
	
	return found_pid;
	

}

//this is for obtaining csrss 2
HANDLE get_module_pid2(PCWSTR module_name)
{

	UNICODE_STRING WantedImageName;
	HANDLE found_pid = NULL;

	RtlInitUnicodeString(&WantedImageName, (PCWSTR)module_name);
	ULONG bytes = 0;
	PVOID buffer;
	NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, NULL, bytes, &bytes); //ZwQuerySystemInformation params: infoclass, buffer, length, returnlength
	int cnt = 0;

	if (!bytes) {
		UNICODE_STRING string0 = RTL_CONSTANT_STRING(L"ZwQuerySysInfo for PID failed!\n");
		DbgPrint("%zW", &string0);
		return NULL;
	}
	//buffer saves original addr of mem pool for deletion
	buffer = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x4e554c4c); //Tag is NULL, allocates non-paged mem pool pointed to by pointer "modules"

	PSYSTEM_PROCESS_INFORMATION processes = (PSYSTEM_PROCESS_INFORMATION)buffer;

	status = ZwQuerySystemInformation(SystemProcessInformation, processes, bytes, &bytes); //actually load modules info into status ptr

	if (!NT_SUCCESS(status)) {
		UNICODE_STRING string1 = RTL_CONSTANT_STRING(L"ExAllocatePoolWithTag failed, or ZwQuerySysInfo status is NULL when finding PID!\n");
		DbgPrint("%zW", &string1);

		return NULL;
	}

	for (;;) {
		//log("\nProcess name: %ws | Process ID: %d\n", processes->ImageName.Buffer, processes->UniqueProcessId); // Display process information.
		if (RtlEqualUnicodeString(&processes->ImageName, &WantedImageName, TRUE)) {
			if (cnt == 0) {
				++cnt;
				if (processes->NextEntryOffset) {
					processes = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)processes + processes->NextEntryOffset);
				}
				else {
					break;
				}
			}
			else {
				log("%ws second has been found!\n", processes->ImageName.Buffer);
				found_pid = processes->UniqueProcessId;
				break;
			}
			
		}
		else if (processes->NextEntryOffset)
			processes = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)processes + processes->NextEntryOffset);
		else
			break;
	}



	ExFreePoolWithTag(buffer, NULL);


	return found_pid;


}


PVOID get_system_module_export(const char* module_name, LPCSTR routine_name) {

	PVOID lpModule = get_system_module_base(module_name);

	if (!lpModule) {
		return NULL;
	}

	return RtlFindExportedRoutineByName(lpModule, routine_name);
}

bool write_memory(void* address, void* buffer, size_t size) {

	if (!RtlCopyMemory(address, buffer, size)) {
		return false;
	}
	else {
		return true;
	}
}

bool write_to_read_only_memory(void* address, void* buffer, size_t size) {

	PMDL Mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);

	if (!Mdl) {
		return false;
	}

	MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
	PVOID Mapping = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);

	write_memory(Mapping, buffer, size);

	MmUnmapLockedPages(Mapping, Mdl);
	MmUnlockPages(Mdl);
	IoFreeMdl(Mdl);
	
	return true;

}

ULONG64 get_module_base_x64(PEPROCESS proc, UNICODE_STRING module_name) {
	PPEB pPeb = PsGetProcessPeb(proc);

	if (!pPeb) {
		log("process module x64 peb not found");
		return NULL;

	}
	KAPC_STATE state;
	KeStackAttachProcess(proc, &state);
	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

	if (!pLdr) {
		KeUnstackDetachProcess(&state);
		return NULL;
	}

	for (PLIST_ENTRY list = (PLIST_ENTRY)pLdr->ModuleListLoadOrder.Flink; list != &pLdr->ModuleListLoadOrder; list = (PLIST_ENTRY)list->Flink) {

		//looping through linked list
		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);

		if (RtlCompareUnicodeString(&pEntry->BaseDllName, &module_name, TRUE) == NULL) {

			ULONG64 baseAddr = (ULONG64)pEntry->DllBase;
			log("%ws process found, returning..", module_name.Buffer);
			KeUnstackDetachProcess(&state);
			return baseAddr;
		}

	}

	log("%ws process NOT found, exiting.", module_name.Buffer);
	KeUnstackDetachProcess(&state);
	return NULL;

}

bool k_RPM(HANDLE pid, uintptr_t address, void* buffer, SIZE_T size) {

	if (!address || !buffer || !size) {
		log("rpm invalid params");
		return false;
	}

	SIZE_T bytes = 0;
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS process;
	KAPC_STATE state;

	if (PsLookupProcessByProcessId((HANDLE)pid, &process) != STATUS_SUCCESS) {
		log("pslookupprocess in rpm failed");
		return false;
	}
	

	status = MmCopyVirtualMemory(process, (void*)address, (PEPROCESS)PsGetCurrentProcess(), (void*)buffer, size, KernelMode, &bytes);

	if (!NT_SUCCESS(status)) {
		return false;
	}

	return true;



		

}

bool k_WPM(HANDLE pid, uintptr_t address, void* buffer, SIZE_T size) {

	if (!address || !buffer || !size) {
		return false;
	}

	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS process;
	if (PsLookupProcessByProcessId((HANDLE)pid, &process) != STATUS_SUCCESS) {
		return false;
	}

	KAPC_STATE state;
	KeStackAttachProcess((PEPROCESS)process, &state);

	MEMORY_BASIC_INFORMATION info;
	status = ZwQueryVirtualMemory(ZwCurrentProcess(), (PVOID)address, MemoryBasicInformation, &info, sizeof(info), NULL);
	if (!NT_SUCCESS(status)) {
		KeUnstackDetachProcess(&state);
		return false;
	}

	if (((uintptr_t)info.BaseAddress + info.RegionSize) < (address + size))
	{
		KeUnstackDetachProcess(&state);
		return false;
	}

	if (!(info.State & MEM_COMMIT) ||
		(info.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
	{
		KeUnstackDetachProcess(&state);
		return false;
	}


	//if flags indicate can write to the memory
	if ((info.Protect & PAGE_EXECUTE_READWRITE) ||
		(info.Protect & PAGE_EXECUTE_WRITECOPY) ||
		(info.Protect & PAGE_READWRITE) ||
		(info.Protect & PAGE_WRITECOPY))
	{
		RtlCopyMemory((void*)address, buffer, size);
	}
	KeUnstackDetachProcess(&state);
	return true;

}