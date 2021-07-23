#pragma once

#define MAX_NUMBER_OF_PARAMERTERS 10


char* slice_string(const char* str, int start, int end);
char** parse_string(const char* str, const char token,int *argc);
void memcpyToEnd(char* dest, const char* src, int size);