#include "mem.h"



extern RWbuf buffer;
extern HANDLE event_handle;
extern HANDLE event_handle2;


bool issue_comm(Commcode cmd, DWORD64 addr, void* structure, int size) {
	buffer.command = cmd;
	buffer.struct_size = size;
	buffer.offset = addr;
	buffer.structure = (DWORD64)structure;
	//buffer.done = 0;

	SetEvent(event_handle);
	//printf("%s", "command issued!\n");
	if (WaitForSingleObject(event_handle2, INFINITE) == WAIT_FAILED) {
		printf("Failed to lock and wait for event2\n");
	}
	
	//command now finished by kernel
	ResetEvent(event_handle2);
	printf("issuecomm completed\n");
	return true;
}