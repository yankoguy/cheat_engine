#include "stdafx.h"
#include "MemoryScanner.h"

memoryObject* search_value(MemoryBlock* first_block, memoryObject* mo_list_object, int type_length, multitype* value, BOOL is_string);
int get_type_length_from_string(const char* str);
void set_multitype(multitype* val, int type_length, char* value, BOOL is_string);

MemoryBlock* create_memory_block(MEMORY_BASIC_INFORMATION *mbi, HANDLE hProc)
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


memoryObject* create_memory_object(LPVOID addr, int type_lenght,int index, BOOL is_string)
{
	memoryObject *Object = (memoryObject*)malloc(sizeof(memoryObject));
	if (Object == NULL)
	{
		printf("Error in malloc");
		exit(0);
	}
	Object->is_string = is_string;
	Object->index = index;
	Object->addr = addr;
	Object->type_size = type_lenght;
	Object->next = NULL;
	return Object;
}


MemoryBlock* scan_proccess_memory(HANDLE hproc) 
{

	SYSTEM_INFO si;
	MEMORY_BASIC_INFORMATION mbi;
	LPVOID minAddress, maxAddress;
	MemoryBlock *firstBlock = NULL, *Block = NULL;		GetSystemInfo(&si);
	minAddress = si.lpMinimumApplicationAddress; //min mem addr of the process
	maxAddress = si.lpMaximumApplicationAddress; //max mem addr of process

	while (minAddress < maxAddress)
	{
		VirtualQueryEx(hproc, minAddress, &mbi, sizeof(mbi));
		if (mbi.State == MEM_COMMIT && mbi.Protect == PAGE_READWRITE)
		{
			if (!firstBlock) {
				firstBlock = create_memory_block(&mbi, hproc);
				Block = firstBlock;
			}
			else {
				Block->Next = create_memory_block(&mbi, hproc);
				Block = Block->Next;
			}
		}
		minAddress = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
	}
	return firstBlock;
}


int get_number_of_memory_blocks(MemoryBlock* first_block)
{
	int block_counter = 0;
	while (first_block)
	{
		block_counter++;
		first_block = first_block->Next;
	}
	return block_counter;
}

memoryObject* search_value(MemoryBlock* first_block, memoryObject* mo_list_object, int type_length, multitype* value, BOOL is_string)
{
	printf("starts searching...\n");	MemoryBlock* temp=first_block;

	memoryObject* mo_list_head = mo_list_object;

	LPVOID compared_value = (is_string) ? value->string : value;


	int number_of_blocks = get_number_of_memory_blocks(first_block);
	int block_counter = 0;


	while (first_block)
	{
		printf("finish reading : %f percentages\r", 100 * ( (float)block_counter / number_of_blocks ) );
		for (int i = 0; i <= first_block->Size - type_length; i++)
		{
			//becuse strings are pointers and not "real" types they need to be treated diffrently
			if (memcmp(first_block->Buffer + i, compared_value, type_length) == 0)
			{
				memoryObject* mo = create_memory_object((LPVOID)((LPBYTE)first_block->BaseAddress + i), type_length, mo_list_object->index+1,is_string);
				mo_list_object->next = mo;
				mo_list_object = mo;
			}

		}
		first_block = first_block->Next;
		free(temp->Buffer);
		free(temp);
		temp = first_block;

		block_counter += 1;
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
			printf("%d ADDR : 0x%p\tValue_string %s\n", temp_object->index,temp_object->addr, buff);
			free(buff);
		}
		else
		{

			switch (type_length)
			{
				case sizeof(char) :
				{
					char value = 0;
					ReadProcessMemory(hProc, temp_object->addr, &value, sizeof(CHAR), NULL);					printf("%d ADDR : 0x%p\tValue_char %c\n", temp_object->index, temp_object->addr, value);
					break;
				}
				case sizeof(int) :
				{
					int value = 0;

					ReadProcessMemory(hProc, temp_object->addr, &value, sizeof(DWORD), NULL);
					printf("%d ADDR : 0x%p\tValue_int %d\n", temp_object->index, temp_object->addr, value);

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


int set_scanner_data(ScannerData* data, char* type, char* value)
{

	int type_length;

	BOOL is_string;
	type_length = get_type_length_from_string(type, value, &is_string);

	data->is_string = is_string;
	data->type_length = type_length;

	if (type_length == 0) {
		printf("Invalid type: You can enter only char int or string\n");
		return 0;
	}

	multitype multi;
	set_multitype(&multi, type_length, value, is_string);


	data->multi = multi;

	return 1;
}

memoryObject* filter(char* type, char* value , memoryObject* list_head,HANDLE hproc)
{

	memoryObject* new_list_head = create_memory_object(NULL, 0,0,FALSE);
	memoryObject* new_list_memory_object = new_list_head;
	
	ScannerData data;
	if (set_scanner_data(&data, type, value) == 0)
	{
		printf("Could not filter because of an error\n");
		return NULL;
	}


	while (list_head)
	{
		if (data.is_string)
		{
			char* value = malloc(1 + sizeof(char) * data.type_length);
			ReadProcessMemory(hproc, list_head->addr, value, data.type_length, NULL);			if (value == data.multi.dword)
			{
				memoryObject* mo = create_memory_object(list_head->addr, data.type_length, new_list_memory_object->index+1,data.is_string);
				new_list_memory_object->next = mo;
				new_list_memory_object = mo;
			}
		}
		else 
		{
			switch (data.type_length)
			{
			case sizeof(char):
				{
					char value =0;
					ReadProcessMemory(hproc, list_head->addr, &value, data.type_length, NULL);					if (value == data.multi.dword)
					{
						memoryObject* mo = create_memory_object(list_head->addr, data.type_length, new_list_memory_object->index+1,data.is_string);
						new_list_memory_object->next = mo;
						new_list_memory_object = mo;
					}
					break;

				}
				
			case sizeof(int):
			{
				int value=0;
				ReadProcessMemory(hproc, list_head->addr, &value, data.type_length, NULL);				if (value == data.multi.dword)
				{
					memoryObject* mo = create_memory_object(list_head->addr, data.type_length, new_list_memory_object->index + 1,data.is_string);
					new_list_memory_object->next = mo;
					new_list_memory_object = mo;
				}
				break; 
			}

				
			default:
				break;
			}

		}
		list_head = list_head->next;
	}	

	if (new_list_head->next != NULL)
	{
		print_values(new_list_head,data.type_length,hproc,data.is_string);
	}
	return new_list_head;

}

memoryObject* scan_memory(char* type, char* value,HANDLE hproc)
{


	memoryObject* new_list_head = create_memory_object(NULL, 0,0,FALSE);
	memoryObject* new_list_memory_object = new_list_head;

	ScannerData data;
	if (set_scanner_data(&data, type, value) == 0)
	{
		printf("Could not scan beacuse of an error\n");
		return NULL;
	}

	MemoryBlock *firstBlock = scan_proccess_memory(hproc);
	MemoryBlock *Block = firstBlock;	read_process_memory_to_buff(Block);	memoryObject* first_object = create_memory_object(NULL, 0,0,FALSE);
	first_object = search_value(firstBlock, first_object, data.type_length ,&data.multi, data.is_string);

	print_values(first_object,data.type_length, hproc,data.is_string);	return first_object;}
void change_value(char* addr, char* type, char* new_value, HANDLE hproc)
{
	memoryObject* new_list_head = create_memory_object(NULL, 0,0,FALSE);
	memoryObject* new_list_memory_object = new_list_head;

	ScannerData data;
	if (set_scanner_data(&data, type, new_value) == 0)
	{
		printf("Could not filter because of an error\n");
		return NULL;
	}

	//make addr hex value
	char *ptr;
	long address;
	address = strtol(addr, &ptr, 16);
	int bytes_writen;


	//WriteProcessMemory(data.hproc, address, &data.multi, data.type_length, &bytes_writen);

	LPVOID pbuff = (data.is_string) ? data.multi.string : &data.multi;

	WriteProcessMemory(hproc, address, pbuff, data.type_length, &bytes_writen);

	if (bytes_writen < data.type_length)
	{
		printf("Error in WriteProcessMemory\n");
	}

}



void earse_saved_memory_object(memoryObject* list_head, char* str_index_to_earse)
{
	int index = atoi(str_index_to_earse);

	if (index <= 0)
	{
		printf("You can not earse that");
		return;
	}
	memoryObject* memory_object = list_head->next;
	memoryObject* prev_object = list_head;
	BOOL found_note = FALSE;

	while (memory_object)
	{
		if (found_note)
		{
			memory_object->index -= 1;
		}

		if (memory_object->index == index && !found_note)
		{
			found_note = TRUE;
			prev_object->next = memory_object->next;
			
			memoryObject* temp = memory_object;

			prev_object = memory_object;
			memory_object = memory_object->next;

			free(temp);
			//dw
		}
		else 
		{
			prev_object = memory_object;
			memory_object = memory_object->next;
		}

	}
}

int save_value(memoryObject* list_head, memoryObject* scanned_value, char* str_index_to_save)
{
	int index = atoi(str_index_to_save);
	if (index <= 0)
	{
		printf("You can not save this index");
		return 0;
	}
	memoryObject* temp = list_head;

	while (temp->next)
	{
		temp = temp->next;
	}
	while (scanned_value)
	{
		if (scanned_value->index == index) 
		{
			memoryObject* mo = create_memory_object(scanned_value->addr, scanned_value->type_size, temp->index + 1,scanned_value->is_string);
			temp->next = mo;
			return 1;
		}
		scanned_value = scanned_value->next;
	}
	return 0;
}