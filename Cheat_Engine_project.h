#pragma once
#include "MemoryScanner.h"

typedef struct 
{
	int pid; //the pid of the remote process
	memoryObject* addresses_list_head; //pointer to linked list of all the sacnned addresses
	memoryObject* saved_scans; //pointer to linked list of all the saved addresses the user saved
	HANDLE hproc; 
}SCAN_INFORMATION;