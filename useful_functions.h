#pragma once

#define MAX_NUMBER_OF_PARAMERTERS 10
#define BUF_SIZE 256
#define SHARED_MEMORY_FILE_NAME "myFile"
#define END_STREAM_TOKEN '!' //Char that indicates the end of memory transferring

char* slice_string(const char* str, int start, int end);
char** parse_string(const char* str, const char token,int *argc);
void memcpyToEnd(char* dest, const char* src, int size, int max_size);
