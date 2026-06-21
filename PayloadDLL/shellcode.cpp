#include "injector.h"

extern "C" {
    void __stdcall ShellcodeLoader(MAPPING_DATA* pData) {
        if (!pData) return;
        BYTE* pBase = pData->baseAddress;
        auto* pNtHeaders = (IMAGE_NT_HEADERS*)(pBase + ((IMAGE_DOS_HEADER*)pBase)->e_lfanew);
        auto* pOptHeader = &pNtHeaders->OptionalHeader;

        // 1. Relocalización
        auto* pRelocDir = &pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (pRelocDir->Size) {
            auto* pReloc = (IMAGE_BASE_RELOCATION*)(pBase + pRelocDir->VirtualAddress);
            while (pReloc->VirtualAddress) {
                UINT count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* pInfo = (WORD*)(pReloc + 1);
                for (UINT i = 0; i < count; i++) {
                    WORD relType = (WORD)(pInfo[i] >> 12);
                    if (relType == IMAGE_REL_BASED_DIR64) {
                        ULONG_PTR* pPatch = (ULONG_PTR*)(pBase + pReloc->VirtualAddress + (pInfo[i] & 0xFFF));
                        *pPatch += (ULONG_PTR)pBase - pOptHeader->ImageBase;
                    } else if (relType == IMAGE_REL_BASED_HIGHLOW) {
                        DWORD* pPatch = (DWORD*)(pBase + pReloc->VirtualAddress + (pInfo[i] & 0xFFF));
                        *pPatch += (DWORD)((ULONG_PTR)pBase - pOptHeader->ImageBase);
                    }
                }
                pReloc = (IMAGE_BASE_RELOCATION*)((BYTE*)pReloc + pReloc->SizeOfBlock);
            }
        }

        // 2. IAT
        auto* pImportDir = &pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (pImportDir->Size) {
            auto* pImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)(pBase + pImportDir->VirtualAddress);
            while (pImportDesc->Name) {
                HMODULE hMod = ((HMODULE(WINAPI*)(char*))pData->fLoadLibraryA)((char*)(pBase + pImportDesc->Name));
                auto* pThunk = (IMAGE_THUNK_DATA*)(pBase + pImportDesc->FirstThunk);
                auto* pIAT = (IMAGE_THUNK_DATA*)(pBase + pImportDesc->OriginalFirstThunk);
                if (!pIAT) pIAT = pThunk;
                while (pIAT->u1.AddressOfData) {
                    FARPROC f = ((FARPROC(WINAPI*)(HMODULE, char*))pData->fGetProcAddress)(hMod, (char*)(pBase + pIAT->u1.AddressOfData + 2));
                    pThunk->u1.Function = (ULONG_PTR)f;
                    pIAT++; pThunk++;
                }
                pImportDesc++;
            }
        }

        // 3. EntryPoint
        if (pOptHeader->AddressOfEntryPoint) {
            ((BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID))(pBase + pOptHeader->AddressOfEntryPoint))((HINSTANCE)pBase, DLL_PROCESS_ATTACH, NULL);
        }
    }
    void __stdcall ShellcodeEnd() {}
}