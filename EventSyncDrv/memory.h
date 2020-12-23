#pragma once
#include "definitions.h"

PVOID get_system_module_base(const char* module_name);
PVOID get_system_module_export(const char* module_name, LPCSTR routine_name);
bool write_memory(void* address, void* buffer, size_t size);
bool write_to_read_only_memory(void* address, void* buffer, size_t size);
HANDLE get_module_pid(PCWSTR module_name);

HANDLE get_module_pid2(PCWSTR module_name);
ULONG64 get_module_base_x64(PEPROCESS proc, UNICODE_STRING module_name);
bool k_RPM(HANDLE pid, uintptr_t address, void* buffer, SIZE_T size);
bool k_WPM(HANDLE pid, uintptr_t address, void* buffer, SIZE_T size);
