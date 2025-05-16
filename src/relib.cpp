/*!
 * @file relib.cpp
 * @author undisassemble
 * @brief relib core functions
 * @version 0.0.0
 * @date 2025-05-16
 * @copyright MIT License
 */

#define _RELIB_INTERNAL
#include "relib/relib.hpp"

RELIB_EXPORT ReLibMetrics_t ReLibMetrics;
ReLibData_t ReLibData;

RELIB_EXPORT void Buffer::Merge(_In_ Buffer Other, _In_ bool bFreeOther) {
    if (!Other.pBytes || !Other.u64Size) {
        return;
    } else if (!pBytes || !u64Size) {
        pBytes = Other.pBytes;
        u64Size = Other.u64Size;
    } else {
        Allocate(u64Size + Other.u64Size);
        memcpy(pBytes + u64Size - Other.u64Size, Other.pBytes, Other.u64Size);
        if (bFreeOther) {
            Other.Release();
        }
    }
}

RELIB_EXPORT void Buffer::Allocate(_In_ uint64_t Size) {
	if (!Size) {
		Release();
		return;
	}
	ReLibMetrics.Memory.Reserved += Size - u64Size;
	ReLibMetrics.Memory.InUse += Size - u64Size;
	u64Size = Size;
	pBytes = reinterpret_cast<BYTE*>(realloc(pBytes, u64Size));
    if (!pBytes) {
        MessageBoxA(NULL, "Failed to allocate memory", "ReLib crashed", MB_OK | MB_ICONERROR);
        DebugBreak();
        exit(1);
    }
}

RELIB_EXPORT void Buffer::Release() {
    if (pBytes) {
		free(pBytes);
		ReLibMetrics.Memory.Reserved -= u64Size;
		ReLibMetrics.Memory.InUse -= u64Size;
	}
    pBytes = NULL;
    u64Size = 0;
}

RELIB_EXPORT void relib::SetErrorCallback(void (__stdcall *callback)(const char* message, ...)) {
    ReLibData.ErrorCallback = callback;
}

RELIB_EXPORT void relib::SetWarningCallback(void (__stdcall *callback)(const char* message, ...)) {
    ReLibData.WarningCallback = callback;
}

RELIB_EXPORT void relib::SetLoggingCallback(void (__stdcall *callback)(const char* message, ...)) {
    ReLibData.LoggingCallback = callback;
}

RELIB_EXPORT void _BaseLogger(const char* message, ...) {}