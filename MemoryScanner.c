#include "stdafx.h"
#include "MemoryScanner.h"

memoryObject* SearchValue(MemoryBlock* first_block, memoryObject* mo_list_object, int type_length, multitype* value);
int get_type_length_from_string(const char* str);
void set_multitype(multitype* val, int type_length, char* value);


MemoryBlock* CreateMemoryBlock(MEMORY_BASIC_INFORMATION *mbi, HANDLE hProc)
{
	MemoryBlock *Block = (MemoryBlock*)malloc(sizeof(MemoryBlock));
	Block->hProc = hProc;
	Block->BaseAddress = mbi->BaseAddress;
	Block->Size = mbi->RegionSize;
	Block->Buffer = (char*)malloc(mbi->RegionSize);
	Block->Next = NULL;
	return Block;
}


memoryObject* CreateMemoryObject(LPVOID addr, int type_lenght)
{
	memoryObject *Block = (memoryObject*)malloc(sizeof(memoryObject));
	Block->addr = addr;
	Block->type_size = type_lenght;
	Block->next = NULL;
	return Block;
}


MemoryBlock* ScanProcess(int pid,HANDLE* phproc) 
{

	SYSTEM_INFO si;
	MEMORY_BASIC_INFORMATION mbi;
	LPVOID minAddress, maxAddress;
	HANDLE hProc;
	MemoryBlock *firstBlock = NULL, *Block = NULL;	
	hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 0, pid);	*phproc = hProc;	GetSystemInfo(&si);
	minAddress = si.lpMinimumApplicationAddress; //min mem addr of the process
	maxAddress = si.lpMaximumApplicationAddress; //max mem addr of process

	while (minAddress < maxAddress)
	{
		VirtualQueryEx(hProc, minAddress, &mbi, sizeof(mbi));
		if (mbi.State == MEM_COMMIT && mbi.Protect == PAGE_READWRITE)
		{
			if (!firstBlock) {
				firstBlock = CreateMemoryBlock(&mbi, hProc);
				Block = firstBlock;
			}
			else {
				Block->Next = CreateMemoryBlock(&mbi, hProc);
				Block = Block->Next;
			}
		}
		minAddress = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
	}
	return firstBlock;
}

memoryObject* SearchValue(MemoryBlock* first_block, memoryObject* mo_list_object, int type_length, multitype* value)
{
	printf("starts searching...\n");
	memoryObject* mo_list_head = mo_list_object;

	int varible_length = type_length; //how much bytes you need to remove from the scan

	if (varible_length == STRING_TYPE_LENGTH)
	{
		varible_length = strlen(((multitype*)value)->string);
	}

	while (first_block)
	{
		for (int i = 0; i <= first_block->Size - varible_length; i++)
		{
			if (type_length == STRING_TYPE_LENGTH)
			{
				//becuse strings are pointers and not "real" types they need to be threated deffrently
				if (memcmp(first_block->Buffer + i, ((multitype*)value)->string, varible_length) == 0)
				{
					memoryObject* mo = CreateMemoryObject((LPVOID)((LPBYTE)first_block->BaseAddress + i), varible_length);
					mo_list_object->next = mo;
					mo_list_object = mo;
				}

			}
			else
			{

				if (memcmp(first_block->Buffer + i, value, type_length) == 0)
				{
					memoryObject* mo = CreateMemoryObject((LPVOID)((LPBYTE)first_block->BaseAddress + i), type_length);
					mo_list_object->next = mo;
					mo_list_object = mo;
				}
			}
		}
		first_block = first_block->Next;
	}
	printf("finish searching\n");

	return mo_list_head;
}

int get_type_length_from_string(const char* str)
{
	if (strcmp(str, "char") == 0) {
		return sizeof(char);
	}
	else if (strcmp(str, "int") == 0)
	{
		return sizeof(int);
	}
	else if (strcmp(str, "string") == 0)
	{
		return STRING_TYPE_LENGTH;
	}
	return 0;
}




void set_multitype(multitype* val, int type_length, char* value)
{
	switch (type_length)
	{
	case sizeof(BYTE) :
		val->byte = value[0];
		break;
	case sizeof(DWORD) :
		val->dword = atoi(value);
		break;

	case STRING_TYPE_LENGTH:
		val->string = value;
		break;
	}
}


void read_process_memory_to_buff(MemoryBlock* Block)
{
	while (Block)
	{
		//reads process memory
		if (ReadProcessMemory(Block->hProc, Block->BaseAddress, Block->Buffer, Block->Size, NULL) == 0)
		{
			printf("Error in ReadProcessMemory");
		}
		Block = Block->Next;
	}
}


void print_values(memoryObject* first_object,int type_length,HANDLE hProc)
{

	printf("\nstart printing...\n");
	memoryObject* temp_object = first_object->next;

	while (temp_object != NULL)
	{
		switch (type_length)
		{
		case sizeof(char) :
		{
			char value = 0;
			ReadProcessMemory(hProc, temp_object->addr, &value, sizeof(CHAR), NULL);			printf("ADDR : 0x%p\tValue_char %C\n", temp_object->addr, value);

			break;
		}


		case sizeof(int) :
			{


				int value=0;

				ReadProcessMemory(hProc, temp_object->addr, &value, sizeof(DWORD),NULL);
				printf("ADDR : 0x%p\tValue_int %d\n", temp_object->addr, value);

				break;
			}
		default:
		{
			char* buff = malloc(1 + sizeof(char) * temp_object->type_size);
			buff[temp_object->type_size] = '\0';
			ReadProcessMemory(hProc, temp_object->addr, buff, temp_object->type_size ,NULL);
			printf("ADDR : 0x%p\tValue_string %s\n", temp_object->addr, buff);

		}

			break;
		}
		temp_object = temp_object->next;

	}

	printf("\nfinished printing\n");
}


void free_memory(memoryObject* first_object)
{
	memoryObject* memory_object = first_object;
	first_object = first_object->next;
	free(memory_object);
	while (first_object != NULL)
	{
		memory_object = first_object;
		first_object = first_object->next;
		free(memory_object);
	}
}

memoryObject* filter()
{
	return NULL;
}

memoryObject* ScanMemory(int pid, char* type, char* value)
{

	if (pid == 0) {
		printf("Pleas enter a valid pid - not zero\n");
		return NULL;
	}

	int type_length = get_type_length_from_string(type);

	if (type_length == 0) {
		printf("Invalid type\nYou can enter only char int or string\n");
		return NULL;
	}
	multitype val;
	set_multitype(&val, type_length, value);

	memoryObject* first_object = CreateMemoryObject(NULL, 0);
	memoryObject* memory_object;

	MemoryBlock *firstBlock;	HANDLE hProc=NULL;
	firstBlock = ScanProcess(pid, &hProc);

	MemoryBlock *Block = firstBlock;	read_process_memory_to_buff(Block);	first_object = SearchValue(firstBlock, first_object, type_length ,&val);

	print_values(first_object,type_length, hProc);	return first_object;}
void change_value(int pid, char* addr, char* type, char* new_value)
{
	//make addr hex value
	char *ptr;
	long address;
	address = strtol(addr, &ptr, 16);

	int type_length = get_type_length_from_string(type);
	multitype val;
	set_multitype(&val, type_length, new_value);

	int bytes_writen;

	HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 0, pid);
	if (hProc == NULL) 
	{
		printf("Error in OpenProcess for writing");
	}
	if (type_length == STRING_TYPE_LENGTH)
	{
		//WriteProcessMemory(hProc, address, (LPVOID)&new_value, strlen(((multitype*)val)->string), &bytes_writen);
	}
	else
	{
		WriteProcessMemory(hProc, address, &val, type_length, &bytes_writen);
		if (bytes_writen < type_length) 
		{
			printf("Error in WriteProcessMemory");
		}
	}
}