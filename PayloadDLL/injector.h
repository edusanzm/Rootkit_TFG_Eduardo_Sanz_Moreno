#pragma once
#include <windows.h>
#include <vector>

struct MAPPING_DATA {
    void* fLoadLibraryA;
    void* fGetProcAddress;
    BYTE* baseAddress;
};

#ifdef __cplusplus
extern "C" {
#endif
    // Ahora ManualMap acepta un vector de bytes, no una ruta de archivo
    bool ManualMap(HANDLE hProc, const std::vector<BYTE>& rawData);
#ifdef __cplusplus
}
#endif