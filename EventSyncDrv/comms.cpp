#include "comms.h"

extern HANDLE um_pid;     //reference handle to usermode control process
HANDLE target_pid = NULL; //reference handle to usermode target process
extern ULONG64 um_base64;
extern PKEVENT sync_event;
extern PKEVENT sync_event2;

extern DWORD64 g_buffer_addr;
enum Commcode {
	COMMAND_RPM = 1,
	COMMAND_WPM,
	COMMAND_GET_UM_PROC_BASE,
	COMMAND_QUIT
};

// for get um proc base, put ptr to string of proc name into structure, base is returned in addr 

// read write buffer for communication between drv and usermode proc
struct RWbuf {
	int command;
	int struct_size = 0;
	DWORD64 offset;
	DWORD64 structure;
	//int done = 1;
};


BYTE temp_buffer[0x2FF0] = { 0 }; //temporary buffer in kernel
bool comms::read_shared_buf(){
	
	if (target_pid == NULL) {
		log("target pid is null!");
	}
	

	
	
	RWbuf KM_buf; //set up temp buff for holding shared mem buff in KM




	log("waiting for UM to set event 1");
	KeWaitForSingleObject(sync_event, Executive, KernelMode, TRUE, nullptr); //wait for UM to unlock buffer
	//log("WAIT PASSED THROUGH");
	//entering critical section start
	k_RPM(um_pid, g_buffer_addr, &KM_buf, sizeof(RWbuf)); //copy shared mem buff into KM buff
	KeClearEvent(sync_event);  //lock buffer
	log("command: %i", KM_buf.command);

	



	log("cmd: %i",KM_buf.command);
	log("size: %i",KM_buf.struct_size);
	log("offset: %llx",KM_buf.offset);
	log("structure: %llx",KM_buf.structure);

	
	//perform actions according to command given from usermode proc
	
	if (KM_buf.command == COMMAND_RPM) {

		//read memory from target um proc, read memory structure is placed in temp_buffer, then fowarded(written) to buffer in um control proc
		RtlSecureZeroMemory(&temp_buffer, sizeof(temp_buffer));
		if (!k_RPM(target_pid, (uintptr_t)KM_buf.offset, &temp_buffer, KM_buf.struct_size)) {
			//read from game_proc to kernel buff
			//log("step 1 fail");
		}
		if (!k_WPM(um_pid, KM_buf.structure, &temp_buffer, KM_buf.struct_size)) {
			//write from kernel buff to UM proc
			//log("step 2 fail");
		}
		//log("rpm done");
	}
	else if (KM_buf.command == COMMAND_WPM) {

		//write memory to target um proc, structure given by um control proc is placed in temp_buffer, then written to target um proc
		RtlSecureZeroMemory(&temp_buffer, sizeof(temp_buffer));
		k_RPM(um_pid, (uintptr_t)KM_buf.structure, &temp_buffer, KM_buf.struct_size);   //read from UM proc to kernel buff
		k_WPM(target_pid, KM_buf.offset, &temp_buffer, KM_buf.struct_size);   //write from kernel buff to game_proc
		//log("wpm done");
	}
	else if (KM_buf.command == COMMAND_GET_UM_PROC_BASE) {

		//retreive target um proc base address, temporarily store in game_name buffer, then write into structure inside um control proc
		BYTE game_name[64] = {0};
		k_RPM(um_pid, KM_buf.structure, &game_name, KM_buf.struct_size);
		
		UNICODE_STRING u_game_name;
		RtlInitUnicodeString(&u_game_name, (PCWSTR)game_name);
		log("um target name requested is : %ws", u_game_name.Buffer);

		target_pid = get_module_pid((PCWSTR)game_name);
		while (target_pid == NULL) {
			log("Get module pid failed, retrying...");
			Sleep(2000);
			target_pid = get_module_pid((PCWSTR)game_name);
		}

		DWORD64 game_base = 0;
		PEPROCESS game_process;
		if (PsLookupProcessByProcessId(target_pid, &game_process) != STATUS_SUCCESS) {
			return false;
		}

		log("ok here");

		game_base = get_module_base_x64(game_process, u_game_name);
		while (game_base == 0) {
			Sleep(2000);
			game_base = get_module_base_x64(game_process, u_game_name);
		}
		k_WPM(um_pid, KM_buf.offset, &game_base, sizeof(DWORD64));

		log("ok here 2");

	}
	else if (KM_buf.command == COMMAND_QUIT) {
		//Quit using driver
		KeSetEvent(sync_event2,HIGH_PRIORITY,FALSE);
		return false;
	}


	//set event2 to allow um to work on buffer
	log("setting event2 to allow um to work on buffer");
	KeSetEvent(sync_event2,HIGH_PRIORITY,FALSE);



	return true;


}

