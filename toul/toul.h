#pragma once

#ifdef EXPORTING_DLL
//extern "C" __declspec(dllexport) void myFunc(PTSTR szSubkey);
extern "C" __declspec(dllexport) DWORD WINAPI GetModuleFileNameExW();
//#else
//extern __declspec(dllimport) void myFunc(PTSTR szSubkey);
#endif