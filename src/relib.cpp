/*!
 * @file relib.cpp
 * @author undisassemble
 * @brief ReLib core functions
 * @version 0.0.0
 * @date 2025-05-25
 * @copyright MIT License
 */

#define _RELIB_INTERNAL
#include "relib/relib.hpp"
#include <stdlib.h>

RELIB_EXPORT ReLibMetrics_t ReLibMetrics;
RELIB_EXPORT _ReLibData_t _ReLibData;

RELIB_EXPORT void Buffer::Merge(_In_ Buffer Other, _In_ bool bFreeOther) {
    if (!Other.pBytes || !Other.szBytes) {
        return;
    } else if (!pBytes || !szBytes) {
        Allocate(Other.Size());
        RELIB_ASSERT(!memcpy_s(pBytes, szBytes, Other.Data(), Other.Size()));
    } else {
        Allocate(szBytes + Other.szBytes);
        memcpy(pBytes + szBytes - Other.szBytes, Other.pBytes, Other.szBytes);
    }
    if (bFreeOther) {
        Other.Release();
    }
}

RELIB_EXPORT void Buffer::Allocate(_In_ size_t Size) {
	if (Size == szBytes) return;
    if (!Size) {
		Release();
		return;
	}
    size_t szToZero = 0;
    if (szBytes < Size) szToZero = Size - szBytes;
	ReLibMetrics.Memory.Reserved += Size;
    ReLibMetrics.Memory.InUse -= szBytes;
	szBytes = Size;
	pBytes = reinterpret_cast<BYTE*>(realloc(pBytes, szBytes));
    RELIB_ASSERT(pBytes != NULL);
    ZeroMemory(pBytes + szBytes - szToZero, szToZero);
}

RELIB_EXPORT void Buffer::Release() {
    if (pBytes) {
		free(pBytes);
		ReLibMetrics.Memory.Reserved -= szBytes;
		ReLibMetrics.Memory.InUse -= szBytes;
	}
    pBytes = NULL;
    szBytes = 0;
}

RELIB_EXPORT void relib::SetErrorCallback(void (__stdcall *callback)(const char* message, ...)) {
    _ReLibData.ErrorCallback = callback;
}

RELIB_EXPORT void relib::SetWarningCallback(void (__stdcall *callback)(const char* message, ...)) {
    _ReLibData.WarningCallback = callback;
}

RELIB_EXPORT void relib::SetLoggingCallback(void (__stdcall *callback)(const char* message, ...)) {
    _ReLibData.LoggingCallback = callback;
}

RELIB_EXPORT void _BaseLogger(const char* message, ...) {}