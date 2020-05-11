#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include "detours.h"

extern "C" __declspec(dllexport) void __stdcall hack(void)
{
	printf("hack.dll: %s\n", __FUNCTION__);
}

static BOOL (WINAPI * Real_CryptImportKey)(HCRYPTPROV hProv, CONST BYTE *pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY *phKey) = CryptImportKey;

BOOL WINAPI Mine_CryptImportKey(HCRYPTPROV hProv, CONST BYTE *pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY *phKey)
{
	char pname[MAX_PATH + 1];
	GetModuleFileName(NULL, pname, MAX_PATH + 1);

	char fpath[MAX_PATH];
	ExpandEnvironmentStrings("%TEMP%\\hack.txt", fpath, MAX_PATH);
	FILE * f = fopen(fpath, "a");

	printf("hack.dll: %s key:", pname);
	if (f)
		fprintf(f, "hack.dll: %s key:", pname);

	for (DWORD i = 0; i < dwDataLen; i++) {

		if (f)
			fprintf(f, "0x%02x ", pbData[i]);
		printf("0x%02x ", pbData[i]);
	}
	printf("\n");

	if (f) {

		fprintf(f, "\n");
		fclose(f);
	}

	return Real_CryptImportKey(hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	LONG error;

	if (fdwReason == DLL_PROCESS_ATTACH) {

		printf("hack.dll: %s\n", __FUNCTION__);

		DetourTransactionBegin();
		DetourAttach(&(PVOID&)Real_CryptImportKey, Mine_CryptImportKey);
		error = DetourTransactionCommit();

		if (error == NO_ERROR) {
			printf("hack.dll: Detoured CryptImportKey().\n");
		}
		else {
			printf("hack.dll: Error detouring CryptImportKey(): %d\n", error);
		}
	}

	return TRUE;
}

