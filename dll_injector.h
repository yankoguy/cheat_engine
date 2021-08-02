#pragma once


#include <Windows.h>

int inject_dll(char* pName);
DWORD find_process_id(const char *  processname);