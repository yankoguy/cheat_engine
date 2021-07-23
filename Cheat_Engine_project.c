// Cheat_Engine_project.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <string.h>
#include <Windows.h>
#include "dll_injector.h"
#include "useful_functions.h"
#include "Cheat_Engine_project.h"
#include <string.h>
#include <conio.h>
#include <tchar.h>

#define MAX_COMMAND_LENGHT 100
#define BUF_SIZE 256
#define SHARED_MEMORY_FILE_NAME "myFile"
#define END_STREAM_TOKEN '!' //Char that indicates the end of memory transferring

void processCommand(char** parsed_str, int argc);
void ProcessDllCommand(char** parsed_str, int argc, char* pBuf);
void scan(char** parsed_str, int argc, char* pBuf);
void help(char** parsed_str, int argc);
char* GetUserInput(int argc);
LPSTR CreateSharedMemory();
HANDLE start(char** parsed_str, int argc);

void program_loop();


enum STATE { COMMAND_STATE, DLL_STATE };


int main()
{
	program_loop();
	return 0;
}

void program_loop()
{
	int state = COMMAND_STATE;

	char* pBuf = CreateSharedMemory(); //create shared memory which will be used later to communicate with the dll
	char* inputBuff;
	char** parsedString;
	int argc = 0;

	while (1)
	{
		inputBuff = GetUserInput(argc);
		parsedString = parse_string(inputBuff, ' ', &argc);
		switch (state)
		{
		case DLL_STATE:
			ProcessDllCommand(parsedString, argc, pBuf);
			break;
		case COMMAND_STATE:
		{
			if (strcmp(parsedString[0], "start") == 0) //check if user typed start which means he now on the DLL_STATE (dll was injected)
			{
				inject_dll(parsedString[1]);
				state = DLL_STATE;
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
			free(parsedString[i]); //PROBLEM
		}
		free(parsedString);
	}
	//printf("freed");

	//if(injector != NULL) CloseHandle(injector);

}

void ProcessDllCommand(char** parsed_str, int argc, char* pBuf)
{
	if (strcmp(parsed_str[0], "scan") == 0)
	{
		scan(parsed_str, argc,pBuf);
	}
}

void processCommand(char** parsed_str, int argc)
{
	if (strcmp(parsed_str[0], "help") == 0)
	{
		help(parsed_str, argc - 1);
	}
}
char* GetUserInput(int argc)
{
	char* buff = (char*)(malloc(MAX_COMMAND_LENGHT));
	int c;
	int count = 0;
	printf("Enter your command: ");

	while ((c = getchar()) != EOF && c != '\n' && count < MAX_COMMAND_LENGHT - 1) {
		buff[count] = c;
		count += 1;
	}
	if (count == 0)
	{
		printf("Pls enter some Command, you can use help to view the commands\n");
	}

	else
	{
		fseek(stdin, 0, SEEK_SET); //sets back the file pointer of stdin to zero in order to avoid reading more than MAX_COMMAND_LENGHT charcters.
		buff[count] = '\0';
	}
	return buff;
}


void scan(char** parsed_str, int argc,char* pBuf)
{
	for (int i = 1; i < argc; i++)
	{
		memcpyToEnd(pBuf, parsed_str[i], strlen(parsed_str[i])); //add one more place
		//memset(pBuf + i, ' ', 1); //change this place to space

	}
	for (int  i = 0; i < BUF_SIZE; i++)
	{
		if (pBuf[i] == '\0') {
			memset(pBuf + i , END_STREAM_TOKEN, 1); //Add token at the end of the line in oreder to indecte the line is over
			break;
		}
	}

	printf(pBuf);

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