#pragma once
#include <Windows.h>

#define STRING_TYPE_LENGTH -1

void change_value(int pid,char* addr, char* type, char* new_value);

typedef struct memoryObject
{
	int type_size;
	void* addr;
	struct memoryObject* next;

}memoryObject;

void free_memory(memoryObject* first_object);

memoryObject* ScanMemory(int pid, char* type, char* value);
memoryObject* filter();



typedef union
{
	BYTE byte;
	DWORD dword;
	CHAR* string;
}multitype;


typedef struct MemoryBlock //linked list
{
	HANDLE hProc;
	LPVOID BaseAddress;
	SIZE_T Size;
	char *Buffer;
	struct MemoryBlock *Next;
}MemoryBlock;