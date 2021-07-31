#include "stdafx.h"
#include "MemoryScanner.h"

memoryObject* SearchValue(MemoryBlock* first_block, memoryObject* mo_list_object, int type_length, multitype* value, BOOL is_string);
int get_type_length_from_string(const char* str);
void set_multitype(multitype* val, int type_length, char* value, BOOL is_string);


MemoryBlock* CreateMemoryBlock(MEMORY_BASIC_INFORMATION *mbi, HANDLE hProc)
{
	MemoryBlock *Block = (MemoryBlock*)malloc(sizeof(MemoryBlock));
	if (Block == NULL)
	{
		printf("Error in malloc");
		exit(0);
	}
	Block->hProc = hProc;
	Block->BaseAddress = mbi->BaseAddress;
	Block->Size = mbi->RegionSize;
	Block->Buffer = (char*)malloc(mbi->RegionSize); 
	if (Block->Buffer == NULL)
	{
		printf("Error in malloc");
		exit(0);
	}
	Block->Next = NULL;
	return Block;
}


memoryObject* CreateMemoryObject(LPVOID addr, int type_lenght)
{
	memoryObject *Object = (memoryObject*)malloc(sizeof(memoryObject));
	if (Object == NULL)
	{
		printf("Error in malloc");
		exit(0);
	}
	Object->addr = addr;
	Object->type_size = type_lenght;
	Object->next = NULL;
	return Object;
}


MemoryBlock* scan_proccess_memory(int pid,HANDLE* phproc) 
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

memoryObject* SearchValue(MemoryBlock* first_block, memoryObject* mo_list_object, int type_length, multitype* value, BOOL is_string)
{
	printf("starts searching...\n");	MemoryBlock* temp=first_block;

	memoryObject* mo_list_head = mo_list_object;

	LPVOID compared_value = (is_string) ? value->string : value;

	while (first_block)
	{
		for (int i = 0; i <= first_block->Size - type_length; i++)
		{
			//becuse strings are pointers and not "real" types they need to be treated diffrently
			if (memcmp(first_block->Buffer + i, compared_value, type_length) == 0)
			{
				memoryObject* mo = CreateMemoryObject((LPVOID)((LPBYTE)first_block->BaseAddress + i), type_length);
				mo_list_object->next = mo;
				mo_list_object = mo;
			}

		}
		first_block = first_block->Next;
		free(temp->Buffer);
		free(temp);
		temp = first_block;
	}
	printf("finish searching\n");

	return mo_list_head;
}

int get_type_length_from_string(const char* str,char* value,BOOL* is_string)
{
	*is_string = FALSE;
	if (strcmp(str, "char") == 0) {
		return sizeof(char);
	}
	else if (strcmp(str, "int") == 0)
	{
		return sizeof(int);
	}
	else if (strcmp(str, "string") == 0)
	{
		*is_string = TRUE;
		return strlen(value);
	}
	return 0;
}




void set_multitype(multitype* val, int type_length, char* value, BOOL is_string)
{
	if (is_string)
	{
		val->string = value;
	}
	else
	{
		switch (type_length)
		{
		case sizeof(BYTE) :
			val->byte = value[0];
			break;
		case sizeof(DWORD) :
			val->dword = atoi(value);
			break;
		}
	}
}


void read_process_memory_to_buff(MemoryBlock* Block)
{

	//we need to read the remote process's memory to a buffer in order to compare it's value with the value that we scan.
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


void print_values(memoryObject* first_object, int type_length, HANDLE hProc, BOOL is_string)
{

	printf("\nstart printing...\n");
	memoryObject* temp_object = first_object->next;
	//do if else
	while (temp_object != NULL)
	{
		if (is_string)
		{
			char* buff = malloc(1 + sizeof(char) * temp_object->type_size);
			if (buff == NULL)
			{
				printf("Error in malloc");
				exit(0);
			}
			buff[temp_object->type_size] = '\0';
			ReadProcessMemory(hProc, temp_object->addr, buff, temp_object->type_size, NULL);
			printf("ADDR : 0x%p\tValue_string %s\n", temp_object->addr, buff);
			free(buff);
		}
		else
		{

			switch (type_length)
			{
				case sizeof(char) :
				{
					char value = 0;
					ReadProcessMemory(hProc, temp_object->addr, &value, sizeof(CHAR), NULL);					printf("ADDR : 0x%p\tValue_char %c\n", temp_object->addr, value);
					break;
				}
				case sizeof(int) :
				{
					int value = 0;

					ReadProcessMemory(hProc, temp_object->addr, &value, sizeof(DWORD), NULL);
					printf("ADDR : 0x%p\tValue_int %d\n", temp_object->addr, value);

					break;
				}

				default:
					break;
			}
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




void scanner()
{
}


memoryObject* filter(int pid,char* type, char* value , memoryObject* list_head)
{

	if (pid == 0) {
		printf("Pleas enter a valid pid - not zero\n");
		return NULL;
	}

	BOOL is_string;
	int type_length = get_type_length_from_string(type,value,&is_string);

	if (type_length == 0) {
		printf("Invalid type\nYou can enter only char int or string\n");
		return NULL;
	}

	multitype val;
	set_multitype(&val, type_length, value,is_string);

	memoryObject* new_list_head= CreateMemoryObject(NULL, 0);
	memoryObject* new_list_memory_object = new_list_head;

	HANDLE hProc = NULL;


	MemoryBlock* firstBlock = scan_proccess_memory(pid, &hProc);

	MemoryBlock *Block = firstBlock;	read_process_memory_to_buff(Block);
	while (list_head)
	{
		if (type_length == 4)
		{
			int value = 0;
			ReadProcessMemory(hProc, list_head->addr, &value, type_length, NULL);			if (value == val.dword)
			{	
				memoryObject* mo = CreateMemoryObject(list_head->addr, type_length);
				new_list_memory_object->next = mo;
				new_list_memory_object = mo;
			}

		}

		/*
		if (type_length == STRING_TYPE_LENGTH)
		{
			//becuse strings are pointers and not "real" types they need to be threated deffrently
			if (memcmp(list_head->addr, (&val)->string, type_length) == 0)
			{
				memoryObject* new_mo = CreateMemoryObject(list_head->addr, type_length);
				new_list_memory_object->next = new_mo;
				new_list_memory_object = new_mo;
			}

		}
		else
		{
			printf("%p\n", list_head->addr);
			if (memcmp(list_head->addr, &val, type_length) == 0)
			{
				memoryObject* mo = CreateMemoryObject(list_head->addr, type_length);
				new_list_memory_object->next = mo;
				new_list_memory_object = mo;

			}
		}
		*/
		list_head = list_head->next;
	}
	if (new_list_head->next != NULL)
	{
		print_values(new_list_head,type_length,hProc,is_string);
	}
	return new_list_head;
}

memoryObject* ScanMemory(int pid, char* type, char* value)
{

	if (pid == 0) {
		printf("Pleas enter a valid pid - not zero\n");
		return NULL;
	}
	BOOL is_string;
	int type_length = get_type_length_from_string(type,value,&is_string);

	if (type_length == 0) {
		printf("Invalid type\nYou can enter only char int or string\n");
		return NULL;
	}
	multitype val;
	set_multitype(&val, type_length, value,is_string);

	memoryObject* first_object = CreateMemoryObject(NULL, 0);
	
	HANDLE hProc = NULL;
	MemoryBlock *firstBlock = scan_proccess_memory(pid, &hProc);
	MemoryBlock *Block = firstBlock;	read_process_memory_to_buff(Block);	first_object = SearchValue(firstBlock, first_object, type_length ,&val, is_string);

	print_values(first_object,type_length, hProc,is_string);	return first_object;}
void change_value(int pid, char* addr, char* type, char* new_value)
{
	//make addr hex value
	char *ptr;
	long address;
	address = strtol(addr, &ptr, 16);

	BOOL is_string;
	int type_length = get_type_length_from_string(type, new_value, &is_string);

	multitype val;
	set_multitype(&val, type_length, new_value,is_string);

	int bytes_writen;

	HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 0, pid);
	if (hProc == NULL) 
	{
		printf("Error in OpenProcess for writing");
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