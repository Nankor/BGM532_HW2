//BASE64, XOR, RC4 fonksiyonlarý için
#include "SifreAlgs.h"

/* aaaack but it's fast and const should make it shared text page. */
static const unsigned char pr2six[256] =
{
	/* ASCII table */
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
	64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
	64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

int Base64decode_len(const char *bufcoded)
{
	int nbytesdecoded;
	register const unsigned char *bufin;
	register int nprbytes;

	bufin = (const unsigned char *)bufcoded;
	while (pr2six[*(bufin++)] <= 63);

	nprbytes = (bufin - (const unsigned char *)bufcoded) - 1;
	nbytesdecoded = ((nprbytes + 3) / 4) * 3;

	return nbytesdecoded + 1;
}

//bufplain için yeterince yer olması lazım, sonuna /0 koymakta
int Base64decode(char *bufplain, const char *bufcoded)
{
	int nbytesdecoded;
	register const unsigned char *bufin;
	register unsigned char *bufout;
	register int nprbytes;

	bufin = (const unsigned char *)bufcoded;
	while (pr2six[*(bufin++)] <= 63);
	nprbytes = (bufin - (const unsigned char *)bufcoded) - 1;
	nbytesdecoded = ((nprbytes + 3) / 4) * 3;

	bufout = (unsigned char *)bufplain;
	bufin = (const unsigned char *)bufcoded;

	while (nprbytes > 4) {
		*(bufout++) =
			(unsigned char)(pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
		*(bufout++) =
			(unsigned char)(pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
		*(bufout++) =
			(unsigned char)(pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
		bufin += 4;
		nprbytes -= 4;
	}

	/* Note: (nprbytes == 1) would be an error, so just ingore that case */
	if (nprbytes > 1) {
		*(bufout++) =
			(unsigned char)(pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
	}
	if (nprbytes > 2) {
		*(bufout++) =
			(unsigned char)(pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
	}
	if (nprbytes > 3) {
		*(bufout++) =
			(unsigned char)(pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
	}

	*(bufout++) = '\0';
	nbytesdecoded -= (4 - nprbytes) & 3;
	return nbytesdecoded;
}

static const char basis_64[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.";

int Base64encode_len(int len)
{
	return ((len + 2) / 3 * 4) + 1;
}

int Base64encode(char *encoded, const char *string, int len)
{
	int i;
	char *p;

	p = encoded;
	for (i = 0; i < len - 2; i += 3) {
		*p++ = basis_64[(string[i] >> 2) & 0x3F];
		*p++ = basis_64[((string[i] & 0x3) << 4) |
			((int)(string[i + 1] & 0xF0) >> 4)];
		*p++ = basis_64[((string[i + 1] & 0xF) << 2) |
			((int)(string[i + 2] & 0xC0) >> 6)];
		*p++ = basis_64[string[i + 2] & 0x3F];
	}
	if (i < len) {
		*p++ = basis_64[(string[i] >> 2) & 0x3F];
		if (i == (len - 1)) {
			*p++ = basis_64[((string[i] & 0x3) << 4)];
			*p++ = '=';
		}
		else {
			*p++ = basis_64[((string[i] & 0x3) << 4) |
				((int)(string[i + 1] & 0xF0) >> 4)];
			*p++ = basis_64[((string[i + 1] & 0xF) << 2)];
		}
		*p++ = '=';
	}

	*p++ = '\0';
	return p - encoded;
}

//lpszID nin yeterince büyük olması lazım yoksa sorun olur
//dwSize 64 den fazla olamaz
BOOL GetRandomCharSeq(char* lpszData, DWORD dwSize)
{
	//-------------------------------------------------------------------
	// Declare and initialize variables.
	HCRYPTPROV   hCryptProv;
	BYTE         pbData[64];

	//4 ün takı olmasza tam bölünmez sorun olmasın...
	if (dwSize % 4 != 0)
		return FALSE;
	dwSize = dwSize / 4 * 3; //base64 çevrimine hazırlık, ona göre size değişecek
	//dwSize'ın çok küçük veya çok büyük olmaması lazım
	if (dwSize > 64 || dwSize < 6) dwSize = 64;
	//DWORD		 dwSize = 12;

	//-------------------------------------------------------------------
	// Acquire a cryptographic provider context handle.
	if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0))
	{
		// Try to create a new key container
		if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
		{
#ifdef SHOWTEXT
			printf("Error during CryptAcquireContext: 0x%x\n", GetLastError());
#endif  
			return FALSE;
		}
	}

	// Generate a random initialization vector.
	if (!CryptGenRandom(hCryptProv, dwSize, pbData))
	{
#ifdef SHOWTEXT
		printf("Error during CryptGenRandom: 0x%x\n", GetLastError());
#endif 
		return FALSE;
	}

	//base64 ünü al
	Base64encode(lpszData, (const char*)pbData, dwSize);

	//-------------------------------------------------------------------
	// Clean up.
	if (hCryptProv)
	if (!CryptReleaseContext(hCryptProv, 0)){
		return FALSE;
#ifdef SHOWTEXT
		printf("Failed CryptReleaseContext: 0x%x\n", GetLastError());
#endif 
	}

	return TRUE;

} // End of main.