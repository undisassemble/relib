/*!
 * @file util.hpp
 * @author undisassemble
 * @brief Utility definitions
 * @version 0.0.0
 * @date 2025-04-08
 * @copyright MIT License
 */

#pragma once

// Headers
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <shlwapi.h>
#include <commdlg.h>
#include <shellapi.h>
#include <stdint.h>
#include "version.hpp"
typedef uint64_t QWORD;
#ifndef UTIL_STRUCT_ONLY
#include <asmjit/asmjit.h>
#include <Zydis/Zydis.h>
using namespace asmjit;
using namespace x86;

// Logging stuff
#define LOG_SUCCESS "\x1B[32m[+]\x1B[39m "
#define LOG_INFO "\x1B[36m[?]\x1B[39m "
#define LOG_INFO_EXTRA  "\x1B[36m[>]\x1B[39m "
#define LOG_WARNING "\x1B[33m[*]\x1B[39m "
#define LOG_ERROR "\x1B[31m[-]\x1B[39m "
#define MODULE_YAP "YAP"
#define MODULE_VM "VM"
#define MODULE_PACKER "Packer"
#define MODULE_REASSEMBLER "ReAsm"

// Macros
#define IMGUI_TOGGLE(str, var) { bool _TEMP_BOOL = var; if(ImGui::Checkbox(str, &_TEMP_BOOL)) { var = _TEMP_BOOL; } } // Allows ImGui::Checkbox to be used with bitfields
#define ASMJIT_LIBRARY_VERSION_MAJOR(version) ((version & 0xFF0000) >> 16)
#define ASMJIT_LIBRARY_VERSION_MINOR(version) ((version & 0xFF00) >> 8)
#define ASMJIT_LIBRARY_VERSION_PATCH(version) (version & 0xFF)
#define countof(x) (sizeof(x) / sizeof(*x))

const int VMMinimumSize = 21;

enum PackerTypes_t : int {
	YAP,
	Themida,
	WinLicense,
	UPX,
	MPRESS,
	Enigma,
	ExeStealth
};

enum State_t : BYTE {
	Idle,
	Packing,
	Disassembling,
	Assembling
};
#endif // UTIL_STRUCT_ONLY

struct Data_t {
	char Project[MAX_PATH] = { 0 };
	char SaveFileName[MAX_PATH] = { 0 };
	float fTotalProgress = 0.f;
	float fTaskProgress = 0.f;
	char* sTask = NULL;
	State_t State = Idle;
	uint64_t Reserved = 0;
	uint64_t InUse = 0;
	HWND hWnd = NULL;
	bool bParsing : 1 = false;
	bool bUserCancelled : 1 = false;
	bool bUsingConsole : 1 = false;
	bool bRunning : 1 = false;
#ifdef _DEBUG // Using DEBUG_ONLY macro doesn't work
	uint64_t TimeSpentSearching = 0;
	uint64_t TimeSpentFilling = 0;
	uint64_t TimeSpentInserting = 0;
	union {
		uint64_t TimeSpentDisassembling = 0;
		uint64_t TimeSpentAssembling;
	};
#endif
};