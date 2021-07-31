// Cheat_Engine_project.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <string.h>
#include <Windows.h>
#include "dll_injector.h"
#include "Cheat_Engine_project.h"
#include <string.h>
#include <conio.h>
#include <tchar.h>
#include "MemoryScanner.h"
#include "utilities.h"
#include "core_parameters.h"

enum ACTION { NO_ACTION, SCAN, CHANGE, FILTER };
enum STATE { COMMAND_STATE, DLL_STATE };

void processCommand(char** parsed_str, int argc);
int ProcessDllCommand(char* opcode, int argc);
void scan(char** parsed_str, int argc, char* pBuf);
void help(char** parsed_str, int argc);
char* GetUserInput();
void start_injection(char ** parsedString, int* state);
LPSTR CreateSharedMemory();
HANDLE start(char** parsed_str, int argc);
char* GetRawUserInput();
void program_loop();
void run_action(int action, char** parames, char* pBuf, SCAN_INFORMATION* info);


int main()
{	
	SCAN_INFORMATION info;
	info.addresses_list_head = NULL;
	info.pid = 0;

	program_loop(&info);
	return 0;
}

void program_loop(SCAN_INFORMATION* info)
{
	int state = COMMAND_STATE; //should be COMMAND_STATE at first

	char* pBuf = CreateSharedMemory(); //create shared memory which will be used later to communicate with the dll
	char* inputBuff;
	char** parsedString;
	int argc = 0;


	while (1)
	{
		inputBuff = GetUserInput();
		parsedString = parse_string(inputBuff, ' ', &argc);
		switch (state)
		{
		case DLL_STATE:
			run_action(ProcessDllCommand(parsedString[0], argc),parsedString,pBuf,info);
			break;
		case COMMAND_STATE:
		{
			if (strcmp(parsedString[0], "start") == 0) //check if user typed start which means he now on the DLL_STATE (dll was injected)
			{
				info->pid = FindProcessId(parsedString[1]);
				state = DLL_STATE;
				//start_injection(parsedString,&state);
			}
			processCommand(parsedString, argc);
			break;
		}
		default:
			break;
		}


		/*free process*/
		free(inputBuff);
		for (int i = 0; i < argc; i++)
		{
			//		printf("free adress :  %p\n", parsed_str[i]);
			free(parsedString[i]);
		}
		free(parsedString);
	}
	//printf("freed");

	//if(injector != NULL) CloseHandle(injector);

}


void start_injection(char ** parsedString, int* state)
{

	if (inject_dll(parsedString[1]) == 1)
	{
		printf("dll injected\n");
		*state = DLL_STATE;
	}
}

int ProcessDllCommand(char* opcode ,int argc)
{
	if (strcmp(opcode, "scan") == 0)
	{
		if (argc == 3)
		{
			return SCAN;
		}
		else
		{
			printf("For scan command you need to type [type] [value]\n");
		}
	}
	else if (strcmp(opcode, "change") == 0)
	{
		if (argc == 4)
		{
			return CHANGE;
		}
		else
		{
			printf("For change command you need to type [address] [type] [new value]\n");
		}
	}
	else if (strcmp(opcode, "filter") == 0)
	{
		if (argc == 3)
		{
			return FILTER;

		}
		else
		{
			printf("For filter command you need to type [type] [value]\n");
		}

	}
	return NO_ACTION;
}

void run_action(int action, char** parames, char* pBuf, SCAN_INFORMATION* info)
{

	switch (action)
	{
	case SCAN:
		if (info->addresses_list_head)
		{
			free_memory(info->addresses_list_head); //free the memory
		}
		info->addresses_list_head = ScanMemory(info->pid, parames[1], parames[2]);
		break;
	case CHANGE:
		change_value(info->pid, parames[1], parames[2], parames[3]);
		break;
	case FILTER:
	{
		memoryObject* temp = info->addresses_list_head;
		if (info->addresses_list_head)
		{
			info->addresses_list_head = filter(info->pid, parames[1], parames[2], info->addresses_list_head->next);
			free_memory(temp); //free the memory
		}
		break;
	}
	default:
		printf("Pls enter the action you want to take");
		break;
	}	

}

void processCommand(char** parsed_str, int argc)
{
	if (strcmp(parsed_str[0], "help") == 0)
	{
		help(parsed_str, argc - 1);
	}
}




void scan(char** parsed_str, int argc,char* pBuf)
{


	/*
	for (int i = 0; i < argc; i++)
	{
		memcpyToEnd(pBuf, parsed_str[i], 1 + strlen(parsed_str[i]),BUFF_SIZE); //add one more place
		memset(pBuf + strlen(pBuf), ' ', 1); //change this place to space

	}
	for (int  i = 0; i < BUFF_SIZE; i++)
	{
		if (pBuf[i] == '\0') {
			memset(pBuf + i , END_STREAM_TOKEN, 1); //Add token at the end of the line in oreder to indecte the line is over
			break;
		}
	}
	*/


}

void help(char** parsed_str, int argc)
{
	printf("You can use this CE to scan varibles in a game.\nyour poitions are:\nscan\n");
}

LPSTR CreateSharedMemory() {
	//create shred memoery in order to communicate with the injected dll
	HANDLE hMapFile = CreateFileMappingA(
		INVALID_HANDLE_VALUE, // file handle
		NULL, // default security
		PAGE_READWRITE, // read access
		0, // maximum object size (high-order
		   // DWORD)
		BUF_SIZE, // maximum object size (low-order
				  // DWORD)

		SHARED_MEMORY_FILE_NAME);

	if (hMapFile == NULL) {
		printf("Error in CreateFileMappingA %d\n", GetLastError());
		printf("%d\n", GetLastError());
	}

	LPSTR pBuf;

	pBuf = (LPSTR)MapViewOfFile(
		hMapFile, // handle to map object
		FILE_MAP_ALL_ACCESS, // read/write permission
		0, // start point (upper word)
		0, // start point (lower word)
		0); //zero means map the whole file	(starts from the specified offset)

	if (pBuf == NULL) {
		printf("Error in MapViewOfFile %d\n", GetLastError());
	}

	return pBuf;
}
