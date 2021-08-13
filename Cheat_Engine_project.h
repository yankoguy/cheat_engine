#pragma once
#include "MemoryScanner.h"


#define CONFIGURATION_FILE_NAME "configuration.txt"
#define LINE_SIZE 64

typedef struct 
{
	int pid; //the pid of the remote process
	memoryObject* addresses_list_head; //pointer to linked list of all the sacnned addresses
	memoryObject* saved_scans; //pointer to linked list of all the saved addresses the user saved
	HANDLE hproc; 
	int program_state;
}SCAN_INFORMATION;