#pragma once

#include <windows.h>
#include <stdio.h>

//#define SHOWTEXT 1
#undef SHOWTEXT 

int Base64encode(char *encoded, const char *string, int len);
int Base64decode(char *bufplain, const char *bufcoded);
//BOOL GetRandomCharSeq(char* lpszData, DWORD dwSize);
