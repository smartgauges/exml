#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>

//#define TEST_HACK
#ifdef TEST_HACK
#pragma comment (lib, "hack.lib")
extern "C" __declspec(dllexport) void __stdcall hack(void);
#endif

struct key3DES_t
{
	BLOBHEADER hdr;
	DWORD keySize;
	BYTE key[24];
};

//hack.dll: C:\Program Files\JLR\IDS\Runtime\PAG_MCPContainer.exe key:0x08 0x02 0x00 0x00 0x03 0x66 0x00 0x00 0x18 0x00 0x00 0x00 0x59 0x6d 0x5a 0x77 0x5a 0x6c 0x51 0x72 0x51 0x33 0x56 0x34 0x64 0x56 0x6c 0x74 0x4e 0x54 0x41 0x72 0x57 0x45 0x39 0x73 
struct key3DES_t key
{
	{ PLAINTEXTKEYBLOB, CUR_BLOB_VERSION, 0,  CALG_3DES },
	24,
	{ 0x59, 0x6d, 0x5a, 0x77, 0x5a, 0x6c, 0x51, 0x72, 0x51, 0x33, 0x56, 0x34, 0x64, 0x56, 0x6c, 0x74, 0x4e, 0x54, 0x41, 0x72, 0x57, 0x45, 0x39, 0x73 },
};

#define ENCRYPT_BLOCK_SIZE 8
bool process_file(LPSTR filename, const struct key3DES_t * pKey, DWORD dwCryptModeDES, bool encrypt)
{ 
	bool fReturn = false;
	HANDLE hSourceFile = INVALID_HANDLE_VALUE;
	HANDLE hDestinationFile = INVALID_HANDLE_VALUE; 

	PBYTE pbBuffer = NULL; 
	DWORD dwBlockLen; 

	hSourceFile = CreateFileA(filename, FILE_READ_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hSourceFile)
	{ 
		printf("Error opening source file!\n");
		return false;
	} 

	const char * suffix_encrypt = "-encrypted";
	const char * suffix_decrypt = "-decrypted";
	const char * suffix = encrypt ? suffix_encrypt : suffix_decrypt;
	int dst_filename_sz = strlen(filename) + strlen(suffix) + 2;
	char * dst_filename = (char *)malloc(dst_filename_sz);
	strcpy(dst_filename, filename);
	strcat(dst_filename, suffix);
	hDestinationFile = CreateFileA(dst_filename, FILE_WRITE_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hDestinationFile)
	{
		printf("Error opening destination file!\n"); 
		return false;
	}

	HCRYPTPROV hCryptProv = NULL;
	BOOL bRes = ::CryptAcquireContext(&hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0);
	if (!bRes) {

		if (NTE_BAD_KEYSET == ::GetLastError()) {

			bRes = ::CryptAcquireContext(&hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
		}
	}
	if (!bRes)
	{
		printf("Error during CryptAcquireContext!\n");
		return false;
	}

	HCRYPTKEY hKey = NULL;
	bRes = ::CryptImportKey(hCryptProv, (const BYTE *)pKey,  sizeof(struct key3DES_t),  0,  0, &hKey);
	if (!bRes) {

		printf("Error during CryptImportKey!\n");
		return false;
	}

	bRes = ::CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&dwCryptModeDES, 0);
	if (!bRes) {

		printf("Error during CryptSetKeyParam!\n");
		return false;
	}

	dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE; 
	if (!(pbBuffer = (PBYTE)malloc(dwBlockLen)))
	{
		printf("Out of memory!\n"); 
		return false;
	}

	bool fEOF = false;
	do
	{
		DWORD dwCount;
		if (!ReadFile(hSourceFile,  pbBuffer,  dwBlockLen,  &dwCount,  NULL))
		{
			printf("Error reading from source file!\n");
			return false;
		}

		if (dwCount < dwBlockLen)
		{
			fEOF = TRUE;
		}

		if (encrypt) {

			bRes = ::CryptEncrypt(hKey, 0, fEOF, 0, pbBuffer, &dwCount, dwBlockLen);
			if (!bRes) {

				printf("Error during CryptEncrypt!\n");
				return false;
			}
		}
		else {

			bRes = ::CryptDecrypt(hKey, 0, fEOF, 0, pbBuffer, &dwCount);
			if (!bRes) {

				printf("Error during CryptDecrypt!\n");
				return false;
			}
		}

		if (!WriteFile(hDestinationFile, pbBuffer, dwCount, &dwCount, NULL))
		{
			printf("Error writing.\n");
			return false;
		}
	} while(!fEOF);

	fReturn = true;

	if (pbBuffer)
	{
		free(pbBuffer);
	}

	if (hSourceFile)
	{
		CloseHandle(hSourceFile);
	}

	if (hDestinationFile)
	{
		CloseHandle(hDestinationFile);
	}

	if (hKey)
	{
		if (!(CryptDestroyKey(hKey)))
		{
			printf("Error during CryptDestroyKey!\n");
		}
	} 

	if (hCryptProv)
	{
		if (!(CryptReleaseContext(hCryptProv, 0)))
		{
			printf("Error during CryptReleaseContext!\n");
		}
	}

	return fReturn;
}

int main(int argc, char * argv[])
{
#ifdef TEST_HACK
	hack();
#endif

	//test_3des();

	if (argc == 3 && !strcmp(argv[1], "-decrypt"))
	{

		process_file(argv[2], &key, CRYPT_MODE_ECB, false);
	}
	else if (argc == 2)
	{
		process_file(argv[1], &key, CRYPT_MODE_ECB, true);
	}
	else {
		printf("Usage: %s [-decrypt] file", argv[0]);
		return 1;
	}

	return 0;
}

