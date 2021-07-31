#pragma once
#include <Windows.h>

void change_value(int pid,char* addr, char* type, char* new_value);

typedef struct memoryObject
{
	int type_size;
	void* addr;
	struct memoryObject* next;

}memoryObject;

void free_memory(memoryObject* first_object);

memoryObject* ScanMemory(int pid, char* type, char* value);
memoryObject* filter(int pid, char* type, char* value, memoryObject* list_head);



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