#pragma once
#include "memory.h"


namespace basichook
{
	bool call_kernel_function(void* kernel_function_address);
	VOID hook_handler(PVOID called_param1);
	bool unhook_kernel_function();
}