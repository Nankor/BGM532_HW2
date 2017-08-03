#pragma once

#ifdef EXPORTING_DLL
extern "C" __declspec(dllexport) LRESULT CALLBACK CBTProc(_In_  int nCode, _In_ WPARAM wParam, _In_  LPARAM lParam);
//extern "C" __declspec(dllexport) DWORD WINAPI GetModuleFileNameExW();
//#else
//extern __declspec(dllimport) void myFunc(PTSTR szSubkey);
#endif