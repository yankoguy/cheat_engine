#pragma once


#include <Windows.h>

int inject_dll(char* pName);
DWORD FindProcessId(const char *  processname);