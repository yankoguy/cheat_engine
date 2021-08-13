#pragma once


#include <Windows.h>

int inject_dll(int pid, char* dll_path);
DWORD find_process_id(const char *  processname);