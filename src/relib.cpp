/*!
 * @file relib.cpp
 * @author undisassemble
 * @brief ReLib core functions
 * @version 0.0.0
 * @date 2025-05-23
 * @copyright MIT License
 */

#define _RELIB_INTERNAL
#include "relib/relib.hpp"
#include <stdlib.h>

RELIB_EXPORT ReLibMetrics_t ReLibMetrics;
_ReLibData_t RELIB_EXPORT _ReLibData;

RELIB_EXPORT void Buffer::Merge(_In_ Buffer Other, _In_ bool bFreeOther) {
    if (!Other.pBytes || !Other.szBytes) {
        return;
    } else if (!pBytes || !szBytes) {
        Allocate(Other.Size());
        memcpy_s(pBytes, szBytes, Other.Data(), Other.Size());
    } else {
        Allocate(szBytes + Other.szBytes);
        memcpy(pBytes + szBytes - Other.szBytes, Other.pBytes, Other.szBytes);
        if (bFreeOther) {
            Other.Release();
        }
    }
}

RELIB_EXPORT void Buffer::Allocate(_In_ size_t Size) {
	if (!Size) {
		Release();
		return;
	}
	ReLibMetrics.Memory.Reserved += Size - szBytes;
	szBytes = Size;
	pBytes = reinterpret_cast<BYTE*>(realloc(pBytes, szBytes));
    if (!pBytes) {
        _ReLibData.ErrorCallback("Failed to allocate memory (requested %llu bytes)\n", szBytes);
        DebugBreak();
        exit(1);
    }
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