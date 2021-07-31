#pragma once
#include "MemoryScanner.h"

typedef struct 
{
	int pid; //the pid of the remote process
	memoryObject* addresses_list_head; //pointer to linked list of all the sacnned addresses

}SCAN_INFORMATION;