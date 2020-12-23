#include "utilities.h"
#include "memory.h"



void Sleep(int ms) {
	LARGE_INTEGER timeout;
	timeout.QuadPart = ms * -10000;
	KeDelayExecutionThread(KernelMode, FALSE, &timeout);
}




