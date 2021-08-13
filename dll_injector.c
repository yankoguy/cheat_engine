// dll_injector.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <string.h>
#include "dll_injector.h"
#include <tlhelp32.h>
#include <errno.h>
#include "Cheat_Engine_project.h"
#include "core_parameters.h"

typedef void(*PFUNC)(void);
#define FILENAME "C:\\Users\\Maor\\Documents\\Visual Studio 2015\\Projects\\project_to_iat_hooking\\file.txt"

int inject_dll(int pid, char* dll_path)
{					
	if (pid == 0)
	{
		printf("Error in dll injection - no process selected to\n");
		return 0;
	}
	// Get LoadLibrary function address –	
	// the address doesn't change at remote process
	PVOID addrLoadLibrary =
		(PVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"),"LoadLibraryA");
	if (addrLoadLibrary == NULL) {
		printf("ERROR in GetProcAddress\n");
		return 0;
	}

	//Get pid by name
	if (pid == 0)
	{
		printf("Error counld not found a process with this name\n");
		return 0;
	}
	// Open remote process
	HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (proc == NULL) {
		printf("ERROR in OpenProcess\n");
		return 0;
	}


	// Get a pointer to memory location in remote process,
	// big enough to store DLL path
	PVOID memAddr = (PVOID)VirtualAllocEx(proc, 0, BUF_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (NULL == memAddr) {
		printf("ERROR in VirtualAllocEx\n");
		return 0;
	}

	// Write DLL name to remote process memory


	BOOL check = WriteProcessMemory(proc, memAddr, dll_path, strlen(dll_path)+1, 0);
	if (0 == check) {
		printf("ERROR in WriteProcessMemory\n");
		return 0;
	}


	// Open remote thread, while executing LoadLibrary
	// with parameter DLL name, will trigger DLLMain

	HANDLE hRemote = CreateRemoteThread(proc, NULL, 0, (LPTHREAD_START_ROUTINE)addrLoadLibrary, memAddr, 0, NULL);
	if (NULL == hRemote) {
		printf("ERROR in CreateRemoteThread: %d\n", GetLastError());
		return 0;
	}
	

	WaitForSingleObject(hRemote, INFINITE);

	CloseHandle(hRemote);
	return 1;
}



DWORD find_process_id(const char *processname)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	DWORD result = 0;

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcessSnap) return(FALSE);

	pe32.dwSize = sizeof(PROCESSENTRY32); 
									 
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);          // clean the snapshot object
		printf("Failed to gather information on system processes! \n");
		return(0);
	}

	do
	{
		//printf("Checking process %ls\n", pe32.szExeFile);
		wchar_t  ws[BUF_SIZE];
		size_t outSize;
		size_t size = strlen(processname) + 1;

		mbstowcs_s(&outSize, ws, size, processname, size-1);
		if (wcscmp(ws, pe32.szExeFile) == 0)
		{
			result = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);

	if (result == 0) {
		printf("Error in FindProcessId - could not find the pid for this process");
	}

	return result;
}