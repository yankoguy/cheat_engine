#pragma once
#include <Windows.h>

void change_value(char* addr, char* type, char* new_value, HANDLE hproc);

typedef struct memoryObject
{
	int index;
	int type_size;
	void* addr;
	BOOL is_string;
	struct memoryObject* next;

}memoryObject;

void free_memory(memoryObject* first_object);

memoryObject* scan_memory(char* type, char* value, HANDLE hproc);
memoryObject* filter(char* type, char* value, memoryObject* list_head, HANDLE hproc);
int save_value(memoryObject* list_head, memoryObject* scanned_value, char* str_index);
void print_values(memoryObject* first_object, int type_length, HANDLE hProc, BOOL is_string);
memoryObject* create_memory_object(LPVOID addr, int type_lenght, int index, BOOL is_string);
void earse_saved_memory_object(memoryObject* list_head, char* index_to_earse);

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


typedef struct
{
	int pid;
	multitype multi;
	int type_length;
	BOOL is_string;
	//HANDLE hproc;
}ScannerData;
