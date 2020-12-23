#pragma once
#include "definitions.h"


void Sleep(int ms);
bool is_key_down(UINT8 const vk);
bool was_key_pressed(UINT8 const vk);
void update_key_state_bitmap(PEPROCESS csrss_proc, PVOID* gafAsyncKeyState);