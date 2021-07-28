#include "stdafx.h"
#include <string.h>
#include <malloc.h>
#include "useful_functions.h"
#include <stdlib.h>


char* slice_string(const char* str, int start, int end) {
	/*Malloc a new buffer whihc contanis a slices string*/
	char* buffer = (char*)malloc(end-start + 2);

	if (buffer == NULL) {
		printf("Error! memory not allocated.");
		exit(0);
	}

	int counter=0;

	for (int i = start; i <= end; ++i) {
		buffer[counter] = str[i];
		counter++;
	}
	buffer[counter] = '\0';
	return buffer;
}

char** parse_string(const char* str, const char token, int* argc) {
	/*Mllocs a new buffer that points to 10 strings (should be freed)*/
	int last_slice = 0;
	*argc = 0;
	char** argv = (char**)malloc(MAX_NUMBER_OF_PARAMERTERS*sizeof(char*));

	if (argv == NULL) {
		printf("Error! memory not allocated.");
		return NULL;
	}

	char* new_str;
	for (int i = 0; i < strlen(str); i++)
	{ 
		if (*argc < MAX_NUMBER_OF_PARAMERTERS) {
			if (str[i] == token)
			{
				new_str = slice_string(str, last_slice, i - 1);
				argv[*argc] = new_str;
				last_slice = i + 1;
				*argc += 1;
			}
			else if (i == strlen(str) - 1) /*i==strlen(str)-1 to slace also the last one*/
			{
				new_str = slice_string(str, last_slice, i);
				argv[*argc] = new_str;
				*argc += 1;

			}
		}
		else {
			printf("You entered too many parametrs - you can only enter %d",MAX_NUMBER_OF_PARAMERTERS-1);
			return argv;
		}
	}
	return argv;
}



void memcpyToEnd(char* dest, const char* src, int size, int max_size) 
{
	//memcpy that writes to the end of the buffer
	int length =0;
	for (int i = 0; dest[i] != '\0'; i++)
	{
		length += 1;
	}
	if (length + strlen(src) < max_size) 
	{
		memcpy(dest + length, src, size);
	}
}
