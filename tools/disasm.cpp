/*!
 * @file disasm.cpp
 * @author undisassemble
 * @brief Dumps disassembly of a file, for debugging.
 * @version 0.0.0
 * @date 2025-08-30
 * @copyright MIT License
 */

#include "relib/asm.hpp"
#include <stdio.h>
#include <windows.h>

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s INPUT [OUTPUT]\n", argv[0]);
        return 0;
    }

    // Open files
    Asm* pAsm = new Asm(argv[1]);
    if (pAsm->Status != Normal) {
        printf("Failed to open file \'%s\' (%d)\n", argv[1], pAsm->Status);
        return 1;
    }

    // Disassemble
    if (!pAsm->Disassemble()) {
        printf("Failed to disassemble\n");
        return 1;
    }
    
    HANDLE hFile = CreateFileA(argc > 2 ? argv[2] : (char*)"dump.txt", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    char buf[MAX_PATH];
    if (!hFile || hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to open output file (%d)\n", GetLastError());
        return 1;
    }

    // Dump function ranges
    for (int i = 0; i < pAsm->GetFunctionRanges().Size(); i++) {
        snprintf(buf, sizeof(buf), "%p -> %p", pAsm->NTHeaders.OptionalHeader.ImageBase + pAsm->GetFunctionRanges()[i].dwStart, pAsm->NTHeaders.OptionalHeader.ImageBase + pAsm->GetFunctionRanges()[i].dwStart + pAsm->GetFunctionRanges()[i].dwSize);
        WriteFile(hFile, buf, lstrlenA(buf), NULL, NULL);
        for (int j = 0; j < pAsm->GetFunctionRanges()[i].Entries.Size(); i++) {
            snprintf(buf, sizeof(buf), ", %p", pAsm->NTHeaders.OptionalHeader.ImageBase + pAsm->GetFunctionRanges()[i].Entries[j]);
            WriteFile(hFile, buf, lstrlenA(buf), NULL, NULL);
        }
        WriteFile(hFile, "\n", 1, NULL, NULL);
    }
    WriteFile(hFile, "\n", 1, NULL, NULL);
    
    // Dump disassembly
    ZydisFormatter fmt;
    ZydisFormatterInit(&fmt, ZYDIS_FORMATTER_STYLE_INTEL);
    for (DWORD dwSec = 0; dwSec < pAsm->GetSections().Size(); dwSec++) {
        AsmSection& sec = pAsm->GetSections().At(dwSec);
        snprintf(buf, sizeof(buf), "Section \'%.8s\' %08lx -> %08lx\n", pAsm->SectionHeaders[dwSec].Name, sec.OldRVA, sec.OldRVA + sec.OldSize);
        WriteFile(hFile, buf, lstrlenA(buf), NULL, NULL);
        if (!sec.Lines) {
            WriteFile(hFile, "NO LINES!\n", 10, NULL, NULL);
            continue;
        }
        for (DWORD i = 0; i < sec.Lines->Size(); i++) {
            snprintf(buf, sizeof(buf), "%08lx\t", sec.Lines->At(i).OldRVA);
            WriteFile(hFile, buf, lstrlenA(buf), NULL, NULL);
            sec.Lines->At(i).ToString(buf, sizeof(buf), fmt);
            WriteFile(hFile, buf, lstrlenA(buf), NULL, NULL);
            WriteFile(hFile, "\n", 1, NULL, NULL);
        }
        WriteFile(hFile, "\n", 1, NULL, NULL);
    }
    CloseHandle(hFile);
    delete pAsm;
    return 0;
}