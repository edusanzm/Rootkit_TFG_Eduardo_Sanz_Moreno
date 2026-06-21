
#include "injector.h"


#include <vector>

extern "C" {
    void __stdcall ShellcodeLoader(MAPPING_DATA* pData);
    void __stdcall ShellcodeEnd();
}

extern "C" bool ManualMap(HANDLE hProc, const std::vector<BYTE>& rawData) {
    if (rawData.empty()) return false;

    auto* pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(const_cast<BYTE*>(rawData.data()));
    auto* pNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(const_cast<BYTE*>(rawData.data()) + pDosHeader->e_lfanew);

    // 1. Reservar memoria en la víctima
    BYTE* pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!pTargetBase) return false;

    // 2. Escribir Headers
    WriteProcessMemory(hProc, pTargetBase, rawData.data(), pNtHeaders->OptionalHeader.SizeOfHeaders, nullptr);

    // 3. Escribir Secciones
    auto* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (UINT i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i, ++pSectionHeader) {
        WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, rawData.data() + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr);
    }

    // 4. Preparar Datos para el Shellcode
    MAPPING_DATA data;
    data.fLoadLibraryA = LoadLibraryA;
    data.fGetProcAddress = GetProcAddress;
    data.baseAddress = pTargetBase;

    BYTE* pDataRemote = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, sizeof(MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!pDataRemote) return false;
    WriteProcessMemory(hProc, pDataRemote, &data, sizeof(MAPPING_DATA), nullptr);

    size_t loaderSize = (uintptr_t)ShellcodeEnd - (uintptr_t)ShellcodeLoader;
    BYTE* pLoaderRemote = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, loaderSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!pLoaderRemote) return false;
    WriteProcessMemory(hProc, pLoaderRemote, (void*)ShellcodeLoader, loaderSize, nullptr);

    // 5. Crear el hilo remoto
    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, (LPTHREAD_START_ROUTINE)pLoaderRemote, pDataRemote, 0, nullptr);
    if (!hThread) return false;

    CloseHandle(hThread);
    return true;
}