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
#include "program_main_params.h"

enum USER_ACTION { NO_ACTION, SCAN, CHANGE, FILTER, SAVE, PRINT, ERASE, START, HELP,PAUSE,RESUME,INJECT};
enum CONFIGURATION_ACTION {SET_FILE_NAME, DLL_TO_INJECT };


int process_command(char* opcode, int argc);
void scan(char** parsed_str, int argc, char* pBuf);
void help();
char* get_user_input();
void start_injection(char ** parsedString, int* state);
LPSTR create_shared_memory();
char* get_user_raw_input();
void program_loop();
void run_action(int action, char** parames, char* pBuf, SCAN_INFORMATION* info);
void set_program_by_configuration_file(SCAN_INFORMATION* info);
int process_configuration_file_line(char* opcode, int argc);
void run_configuration_file_actions(SCAN_INFORMATION* info, int action, char** parames);
void start(SCAN_INFORMATION* info, char* program_name);
void set_scan_information(SCAN_INFORMATION* info);

int main()
{	
	SCAN_INFORMATION info;
	set_scan_information(&info);
	program_loop(&info);
	return 0;
}

void set_scan_information(SCAN_INFORMATION* info)
{
	info->saved_scans = create_memory_object(NULL, 0, 0, FALSE,"");
	info->addresses_list_head = NULL;
	info->pid = 0;
	info->hproc = NULL;
	info->program_state = RUNNING;
	set_program_by_configuration_file(info);
}


void set_program_by_configuration_file(SCAN_INFORMATION* info)
{
	char buff[BUF_SIZE];
	char line[BUF_SIZE];

	HANDLE source = CreateFileA(CONFIGURATION_FILE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (source == INVALID_HANDLE_VALUE) {
		printf("Source file not opened. Error %u", GetLastError());
		return;
	}

	int letter_read = 0;

	if (!ReadFile(source, buff, sizeof(buff), &letter_read, NULL)) {
		printf("Source file not read from. Error %u", GetLastError());
		return;
	}
	
	buff[letter_read] = '\0';

	
	int number_of_lines = 0;
	char** lines = parse_string(buff, '\n', &number_of_lines, 0); //need to be freed
	for (int i = 0; i < number_of_lines; i++)
	{
		if (i != number_of_lines - 1) //if it is not last place
		{
			lines[i][strlen(lines[i]) - 1] = '\0'; //change the '\r' at the end of the line to '\0'
		}
	
		int argc=0;
		char** params = parse_string(lines[i], ':', &argc, '"'); //need to be freed
		run_configuration_file_actions(info,process_configuration_file_line(params[0],argc),params);
		for (int i = 0; i < argc; i++)
		{
			free(params[i]);
		}
		free(lines[i]);
	}


	CloseHandle(source);
	//free stuff
}


int process_configuration_file_line(char* opcode, int argc)
{
	if (strcmp(opcode, "file_name") == 0)
	{
		if (argc == 2)
		{
			return SET_FILE_NAME;
		}
		else
		{
			printf("Error in configuration : file_name\n");
		}
	}
	else if (strcmp(opcode, "dll_to_inject") == 0)
	{
		if (argc == 2)
		{
			return DLL_TO_INJECT;
		}
		else
		{
			printf("Error in configutation : dll_to_inject\n");
		}
	}
}

void run_configuration_file_actions(SCAN_INFORMATION* info,int action, char** parames)
{
	switch (action)
	{
	case SET_FILE_NAME:
		start(info,parames[1]);
		break;
	case DLL_TO_INJECT:
		inject_dll(info->pid, parames[1]);
	default:
		break;
	}
}


void program_loop(SCAN_INFORMATION* info)
{
	char* pBuf = create_shared_memory(); //create shared memory which will be used later to communicate with the dll
	char* inputBuff;
	char** parsedString;
	int argc = 0;


	while (1)
	{
		inputBuff = get_user_input();
		parsedString = parse_string(inputBuff, ' ', &argc, '"');
		if (parsedString != NULL)
		{
			run_action(process_command(parsedString[0], argc), parsedString, pBuf, info);
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


void start(SCAN_INFORMATION* info, char* program_name)
{
	if (info->pid == 0)
	{
		info->pid = find_process_id(program_name);
		if (info->pid != 0)
		{
			info->hproc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 0, info->pid);
			if (info->hproc == NULL)
			{
				printf("Error in OpenProcess\n");
			}
		}
		else
		{
			printf("Could not find the process id\n");
		}
	}
	else 
	{
		printf("You already in choose a program. If you want to choose another program type \"new\"\n");
	}
}



int process_command(char* opcode, int argc)
{
	if (strcmp(opcode, "scan") == 0)
	{
		if (argc == 3)
		{
			return SCAN;
		}
		printf("For scan command you need to type [type] [value]\n");

	}
	else if (strcmp(opcode, "change") == 0)
	{
		if (argc == 4)
		{
			return CHANGE;
		}
		printf("For change command you need to type [address] [type] [new value]\n");

	}
	else if (strcmp(opcode, "filter") == 0)
	{
		if (argc == 3)
		{
			return FILTER;

		}
		printf("For filter command you need to type [type] [value]\n");


	}
	else if (strcmp(opcode, "save") == 0)
	{
		if (argc == 3)
		{
			return SAVE;

		}
		printf("For save command you need to type [index] [name]\n");

	}
	else if (strcmp(opcode, "print") == 0)
	{
		if (argc == 1)
		{
			return PRINT;

		}
		printf("For print command you do not need any arguments\n");

	}
	else if (strcmp(opcode, "erase") == 0)
	{
		if (argc == 2)
		{
			return ERASE;
		}
		printf("For delete command you need to type [index]\n");

	}
	else if (strcmp(opcode, "start")==0)
	{
		if (argc == 2)
		{
			return START;
		}
		printf("For start comamnd you need to type [program_name]\n");


	}
	else if (strcmp(opcode, "pause") == 0)
	{
		if (argc == 1)
		{
			return PAUSE;
		}
		printf("For pausing the game just type pause");

	}
	else if (strcmp(opcode, "resume") == 0)
	{
		if (argc == 1)
		{
			return RESUME;
		}
		printf("For pausing the game just type resume");

	}
	else if (strcmp(opcode, "inject") == 0)
	{
		if (argc == 2)
		{
			return INJECT;
		}
		printf("For injecting dll to game enter dll name pls\n");

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
		info->addresses_list_head = scan_memory(parames[1], parames[2],info->hproc);
		break;
	case CHANGE:
		change_value(parames[1], parames[2], parames[3], info->hproc);
		break;
	case FILTER:
	{
		memoryObject* temp = info->addresses_list_head;
		if (info->addresses_list_head)
		{
			info->addresses_list_head = filter(parames[1], parames[2], info->addresses_list_head->next, info->hproc);
			free_memory(temp); //free the memory
		}
		else {
			printf("You need to scan first in order to filter\n");
		}
		break;
	}
	case SAVE:
		if (save_value(info->saved_scans,info->addresses_list_head,parames[1],parames[2]) == 0)
		{
			printf("Could not scan");
		}
		break;
	case PRINT:
		if (info->saved_scans->next != NULL)
		{
			print_values(info->saved_scans, info->hproc);
		}
		else
		{
			printf("Error could not print - you first need to save scan values\n");

		}
		break;
	case ERASE:
		erase_saved_memory_object(info->saved_scans,parames[1]);
		break;
	case START:
		start(info, parames[1]);
		break;
	case HELP:
		help();
		break;
	case PAUSE:
		if (pause_program(info->pid, info->program_state) == 1)
		{
			info->program_state = PAUSING;
		}
		break;
	case RESUME:
		if (resume_program(info->pid, info->program_state) == 1)
		{
			info->program_state = RUNNING;
		}
		break;
	case INJECT:
		if (inject_dll(info->pid,parames[1]) == 0)
		{
			printf("Could not inject dll\n");
		}
	default:
		break;
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

void help()
{
	printf("You can use this CE to scan varibles in a game.\nyour poitions are:\nstart\nscan\nchange\nfilter\nsave\nerase\nprint\npause\nresume");
}

LPSTR create_shared_memory() {
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
