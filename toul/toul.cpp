#include "../BGM532_HW2/Header.h"
#define EXPORTING_DLL
#include "toul.h"

typedef LRESULT (CALLBACK* CBTProc)(_In_  int nCode, _In_ WPARAM wParam, _In_  LPARAM lParam);


void InjectHook() {
	// hangi prosese inject yapacaksak onun window ismini ��renelim
	HWND hwnd;
	hwnd = FindWindowA("Shell_TrayWnd", NULL);

	if (hwnd == NULL) {
		HATA(L"TOUL: InjectHook", L"FindWindowA");
		return;
	}
	// window isminden gerekli thread IP yi ��renelim
	DWORD pID = 0;
	DWORD ThreadID = GetWindowThreadProcessId(hwnd, &pID);

#ifdef _WIN64
	TCHAR lpFullLibPathName = L"C:/Users/osman/Documents/visual studio 2013/Projects/BGM532_HW2/x64/Debug/kloc.dll";
#else
	TCHAR lpFullLibPathName[MAX_PATH];
	ZeroMemory(lpFullLibPathName, MAX_PATH);
	if (!GetWindowsDirectory(lpFullLibPathName, MAX_PATH)) {
		HATA(L"TOUL: GetWindowsDirectory", TEXT("GetWindowsDirectory"));
		return;
	}

	StringCchCat(lpFullLibPathName, MAX_PATH, L"\\");
	StringCchCat(lpFullLibPathName, MAX_PATH, HOOK_DLL);
#endif

	// hedef prosese dll y�kleme i�leminin bitmesini beklemek i�in
	HANDLE hEvent = CreateEventA(
		NULL, // default security attributes
		TRUE, // manual reset event
		FALSE, // not signaled
		EVENTNAME); // no name

	HMODULE mylib = LoadLibrary(lpFullLibPathName);
	CBTProc myCBTProc = (CBTProc)GetProcAddress(mylib, "CBTProc");

	HHOOK hhkCBT = SetWindowsHookEx(WH_CBT, myCBTProc, mylib, ThreadID);
	// bu i�lemden sonra kar�� tarafta WH_CBT olay� olu�turmam�z laz�m, ama beceremedik

	// hedef proseste dll y�kleme i�lemi bitene kadar s�resiz olarak bekle 
	WaitForSingleObject(hEvent, INFINITE);

	// dll y�kleme bittiyse hook u kald�r
	UnhookWindowsHookEx(hhkCBT);
	CloseHandle(hEvent);
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD fdwReason, LPVOID lpReserved) {
#ifdef _DEBUG_OLD
	CHAR szMsj[64] = "DllMain den selamlar";
	CHAR szTitle[32];
	ZeroMemory(szTitle, 32);	

	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
	// A process is loading the DLL.
		StringCchCopyA(szTitle, 32, "DLL_PROCESS_ATTACH");
		break;
	case DLL_THREAD_ATTACH:
	// A process is creating a new thread.
		StringCchCopyA(szTitle, 32, "DLL_THREAD_ATTACH");
		break;
	case DLL_THREAD_DETACH:
	// A thread exits normally.
		StringCchCopyA(szTitle, 32, "DLL_THREAD_DETACH");
		break;
	case DLL_PROCESS_DETACH:
	// A process unloads the DLL.
		StringCchCopyA(szTitle, 32, "DLL_PROCESS_DETACH");
		break;
	}

	int msgboxID = MessageBoxA(
		NULL,
		szMsj,
		szTitle,
		MB_ICONINFORMATION | MB_OK
		);
#endif

	if (fdwReason == DLL_PROCESS_ATTACH) {
		InjectHook();
#ifdef _DEBUG_old
			MessageBoxA(NULL,
				"DllMain(DLL_PROCESS_ATTACH) CreateThread Failed",
				"TOUL:",
				MB_OK);
#endif
		//}
	}

	return TRUE;
}


DWORD WINAPI GetModuleFileNameExW() {
	return NULL;
}
