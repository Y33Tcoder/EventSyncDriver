#pragma once
#include "includes.h"


//Command codes for issuing commands to driver to do job
enum Commcode {
	COMMAND_RPM = 1,
	COMMAND_WPM,
	COMMAND_GET_UM_PROC_BASE,
	COMMAND_QUIT
};

// for get um proc base, put ptr to string of proc name into structure, base is returned in addr 


// read write buffer for comms
struct RWbuf {
	int command;
	int struct_size = 0;
	DWORD64 offset = 0;
	DWORD64 structure = 0;
	//int done = 1;
};

bool issue_comm(Commcode cmd, DWORD64 addr, void* structure, int size);
