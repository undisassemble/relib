/*!
 * @file pe.cpp
 * @author undisassemble
 * @brief Portable executable parsing functions
 * @version 0.0.0
 * @date 2025-05-23
 * @copyright MIT License
 */

#define _RELIB_INTERNAL
#include <limits.h>
#include <stdlib.h>
#include "relib/pe.hpp"

RELIB_EXPORT PE::PE(_In_ char* sFileName) {
	if (!sFileName) {
		return;
	}

	HANDLE hFile = CreateFileA(sFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hFile || hFile == INVALID_HANDLE_VALUE) {
		Status = NoFile;
		return;
	}
	ParseFile(hFile);
	CloseHandle(hFile);
}

RELIB_EXPORT PE::PE(_In_ HANDLE hFile) {
	ParseFile(hFile);
}

RELIB_EXPORT PE::PE() {}

RELIB_EXPORT PE::~PE() {
	while (SectionData.Size()) {
		Buffer data = SectionData.Pop();
		data.Release();
	}
	SectionData.Release();
	SectionHeaders.Release();
	DosStub.Release();
	Overlay.Release();
	OverlayOffset = 0;
	Status = NotSet;
}

RELIB_EXPORT PE::PE(_In_ PE* pOther) {
	Status = pOther->Status;
	DosHeader = pOther->DosHeader;
	NTHeaders = pOther->NTHeaders;
	DosStub.Allocate(pOther->DosStub.Size());
	memcpy_s(DosStub.Data(), DosStub.Size(), pOther->DosStub.Data(), pOther->DosStub.Size());
	SectionHeaders.Merge(pOther->SectionHeaders);
	for (int i = 0; i < NTHeaders.FileHeader.NumberOfSections; i++) {
		Buffer buf;
		if (pOther->SectionData[i].Size()) {
			buf.Allocate(pOther->SectionData[i].Size());
			memcpy_s(buf.Data(), buf.Size(), pOther->SectionData[i].Data(), pOther->SectionData[i].Size());
		}
		SectionData.Push(buf);
	}
}

RELIB_EXPORT bool PE::ParseFile(_In_ HANDLE hFile) {
	if (hFile == INVALID_HANDLE_VALUE || !hFile) {
		Status = NotSet;
		return false;
	}

	// Read bytes
	Buffer FileData;
	FileData.Allocate(GetFileSize(hFile, NULL));
	if (!ReadFile(hFile, FileData.Data(), FileData.Size(), NULL, NULL)) {
		Status = NoFile;
		return false;
	}

	// DOS header
	memcpy_s(&DosHeader, sizeof(IMAGE_DOS_HEADER), FileData.Data(), sizeof(IMAGE_DOS_HEADER));
	if (DosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		Status = NotPE;
		FileData.Release();
		return false;
	}

	// DOS stub
	DosStub.Allocate(DosHeader.e_lfanew - sizeof(IMAGE_DOS_HEADER));
	memcpy_s(DosStub.Data(), DosStub.Size(), FileData.Data() + sizeof(IMAGE_DOS_HEADER), DosStub.Size());

	// NT headers
	if (DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64) > FileData.Size()) {
		Status = NotPE;
		FileData.Release();
		return false;
	}
	memcpy_s(&NTHeaders, sizeof(IMAGE_NT_HEADERS64), FileData.Data() + DosHeader.e_lfanew, sizeof(IMAGE_NT_HEADERS64));
	if (NTHeaders.Signature != IMAGE_NT_SIGNATURE) {
		Status = NotPE;
		FileData.Release();
		return false;
	}
	
	// Validate architecture
	if (NTHeaders.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
		Status = Unsupported;
		FileData.Release();
		return false;
	} else if (NTHeaders.OptionalHeader.Magic != 0x20B) {
		Status = NotPE;
		FileData.Release();
		return false;
	}

	// Clear empty data dirs
	if (IMAGE_NUMBEROF_DIRECTORY_ENTRIES - NTHeaders.OptionalHeader.NumberOfRvaAndSizes)
		ZeroMemory(&NTHeaders.OptionalHeader.DataDirectory[NTHeaders.OptionalHeader.NumberOfRvaAndSizes], sizeof(IMAGE_DATA_DIRECTORY) * (IMAGE_NUMBEROF_DIRECTORY_ENTRIES - NTHeaders.OptionalHeader.NumberOfRvaAndSizes));

	// Section headers
	if (DosHeader.e_lfanew + NTHeaders.FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + 4 + sizeof(IMAGE_SECTION_HEADER) * NTHeaders.FileHeader.NumberOfSections > FileData.Size()) {
		Status = Corrupt;
		FileData.Release();
		return false;
	} else {
		SectionHeaders.Reserve(NTHeaders.FileHeader.NumberOfSections);
		IMAGE_SECTION_HEADER* pHeaders = reinterpret_cast<IMAGE_SECTION_HEADER*>(FileData.Data() + DosHeader.e_lfanew + NTHeaders.FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + 4);
		for (int i = 0; i < NTHeaders.FileHeader.NumberOfSections; i++) SectionHeaders.Push(pHeaders[i]);
	}

	for (int i = 0; i < SectionHeaders.Size(); i++) {
		Buffer buf;
		if (SectionHeaders[i].SizeOfRawData) {
			if (SectionHeaders[i].PointerToRawData + SectionHeaders[i].SizeOfRawData > FileData.Size()) {
				Status = Corrupt;
				FileData.Release();
				return false;
			} else {
				buf.Allocate(SectionHeaders[i].SizeOfRawData);
				memcpy(buf.Data(), FileData.Data() + SectionHeaders[i].PointerToRawData, buf.Size());
			}
		}
		SectionData.Push(buf);
	}

	// Overlay
	OverlayOffset = SectionHeaders[SectionHeaders.Size() - 1].PointerToRawData + SectionHeaders[SectionHeaders.Size() - 1].SizeOfRawData;
	if (OverlayOffset > FileData.Size()) {
		Status = Corrupt;
		FileData.Release();
		return false;
	} else if (FileData.Size() > OverlayOffset) {
		Overlay.Allocate(FileData.Size() - OverlayOffset);
		memcpy(Overlay.Data(), FileData.Data() + FileData.Size() - Overlay.Size(), Overlay.Size());
	} else {
		OverlayOffset = 0;
	}

	Status = Normal;
	FileData.Release();
	return true;
}


/***** GET FUNCTIONS *****/

RELIB_EXPORT Vector<IMAGE_IMPORT_DESCRIPTOR> PE::GetImportedDLLs() {
	Vector<IMAGE_IMPORT_DESCRIPTOR> ret;
	if (Status || !NTHeaders.OptionalHeader.DataDirectory[1].VirtualAddress || !NTHeaders.OptionalHeader.DataDirectory[1].Size) return ret;
	Buffer buf;
	IMAGE_SECTION_HEADER Header;
	{
		WORD i = FindSectionByRVA(NTHeaders.OptionalHeader.DataDirectory[1].VirtualAddress);
		buf = SectionData[i];
		Header = SectionHeaders[i];
		if (!buf.Data() || !buf.Size() || NTHeaders.OptionalHeader.DataDirectory[1].VirtualAddress + NTHeaders.OptionalHeader.DataDirectory[1].Size - Header.VirtualAddress > buf.Size()) return ret;
	}

	IMAGE_IMPORT_DESCRIPTOR* pTable = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(buf.Data() + NTHeaders.OptionalHeader.DataDirectory[1].VirtualAddress - Header.VirtualAddress);
	IMAGE_IMPORT_DESCRIPTOR zero = { 0 };
	for (int i = 0; NTHeaders.OptionalHeader.DataDirectory[1].Size >= i * sizeof(IMAGE_IMPORT_DESCRIPTOR); i++) {
		if (!memcmp(&zero, &pTable[i], sizeof(IMAGE_IMPORT_DESCRIPTOR))) break;
		ret.Push(pTable[i]);
	}
	return ret;
}

RELIB_EXPORT WORD PE::FindSectionByRaw(_In_ DWORD dwRaw) {
	if (Status || dwRaw >= OverlayOffset)
		return _UI16_MAX;

	for (WORD i = 0; i < SectionHeaders.Size(); i++) {
		if (SectionHeaders[i].PointerToRawData && SectionHeaders[i].VirtualAddress && SectionHeaders[i].PointerToRawData <= dwRaw && SectionHeaders[i].SizeOfRawData >= dwRaw) {
			return i;
		}
	}

	return _UI16_MAX;
}

RELIB_EXPORT WORD PE::FindSectionByRVA(_In_ DWORD dwRVA) {
	if (Status)
		return _UI16_MAX;

	for (WORD i = 0; i < SectionHeaders.Size(); i++) {
		if (SectionHeaders[i].VirtualAddress && SectionHeaders[i].VirtualAddress <= dwRVA && SectionHeaders[i].VirtualAddress + SectionHeaders[i].Misc.VirtualSize >= dwRVA) {
			return i;
		}
	}

	return _UI16_MAX;
}

RELIB_EXPORT DWORD PE::RVAToRaw(_In_ DWORD dwRVA) {
	if (Status)
		return 0;

	WORD wIndex = FindSectionByRVA(dwRVA);
	if (wIndex >= SectionHeaders.Size() || !SectionHeaders[wIndex].PointerToRawData || SectionHeaders[wIndex].SizeOfRawData < dwRVA - SectionHeaders[wIndex].VirtualAddress) return 0;
	return SectionHeaders[wIndex].PointerToRawData + (dwRVA - SectionHeaders[wIndex].VirtualAddress);
}

RELIB_EXPORT DWORD PE::RawToRVA(_In_ DWORD dwRaw) {
	if (Status || dwRaw >= OverlayOffset)
		return 0;

	WORD wIndex = FindSectionByRaw(dwRaw);
	if (wIndex >= SectionHeaders.Size() || !SectionHeaders[wIndex].VirtualAddress || SectionHeaders[wIndex].Misc.VirtualSize < dwRaw - SectionHeaders[wIndex].PointerToRawData) return 0;
	return SectionHeaders[wIndex].VirtualAddress + (dwRaw - SectionHeaders[wIndex].PointerToRawData);
}

RELIB_EXPORT uint64_t* PE::GetTLSCallbacks() {
	if (Status)
		return NULL;

	// Get directory
	IMAGE_DATA_DIRECTORY TLSDataDir = NTHeaders.OptionalHeader.DataDirectory[9];
	if (!TLSDataDir.VirtualAddress)
		return NULL;

	// Getting TLS callback array
	IMAGE_TLS_DIRECTORY64 dir = ReadRVA<IMAGE_TLS_DIRECTORY64>(TLSDataDir.VirtualAddress);
	WORD wIndex = FindSectionByRVA(dir.AddressOfCallBacks - NTHeaders.OptionalHeader.ImageBase);
	if (wIndex >= SectionHeaders.Size() || SectionData[wIndex].Size() - dir.AddressOfCallBacks + NTHeaders.OptionalHeader.ImageBase - SectionHeaders[wIndex].VirtualAddress < sizeof(uint64_t)) return NULL;
	return reinterpret_cast<uint64_t*>(SectionData[wIndex].Data() + dir.AddressOfCallBacks - NTHeaders.OptionalHeader.ImageBase - SectionHeaders[wIndex].VirtualAddress);
}

RELIB_EXPORT IAT_ENTRY* PE::GetIAT() {
	IMAGE_DATA_DIRECTORY IATDir = NTHeaders.OptionalHeader.DataDirectory[1];
	if (!IATDir.VirtualAddress || !IATDir.Size) return NULL;
	WORD i = FindSectionByRVA(IATDir.VirtualAddress);
	if (i >= SectionHeaders.Size() || SectionData[i].Size() - (IATDir.VirtualAddress - SectionHeaders[i].VirtualAddress) < sizeof(IAT_ENTRY)) return NULL;
	return reinterpret_cast<IAT_ENTRY*>(SectionData[i].Data() + (IATDir.VirtualAddress - SectionHeaders[i].VirtualAddress));
}

RELIB_EXPORT void PE::StripDosStub() {
	DosStub.Release();
}

RELIB_EXPORT void PE::RebaseImage(_In_ uint64_t u64NewBase) {
	if (!(NTHeaders.FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)) {
		Vector<DWORD> Relocs = GetRelocations();
		for (int i = 0; i < Relocs.Size(); i++) {
			WriteRVA<uint64_t>(Relocs[i], ReadRVA<uint64_t>(Relocs[i]) - NTHeaders.OptionalHeader.ImageBase + u64NewBase);
		}
		Relocs.Release();
	}
	NTHeaders.OptionalHeader.ImageBase = u64NewBase;
}

RELIB_EXPORT void PE::DeleteSection(_In_ WORD wIndex) {
	// Check valid index
	if (Status || wIndex >= SectionHeaders.Size())
		return;

	// Delete header
	NTHeaders.FileHeader.NumberOfSections--;
	SectionHeaders.Remove(wIndex);

	// Delete data (if any)
	SectionData[wIndex].Release();
	SectionData.Remove(wIndex);
}

RELIB_EXPORT void PE::OverwriteSection(_In_ WORD wIndex, _In_opt_ Buffer Data) {
	// Check valid index
	if (Status || wIndex >= SectionHeaders.Size())
		return;
	
	IMAGE_SECTION_HEADER Header = SectionHeaders[wIndex];
	Header.SizeOfRawData = Data.Size();
	SectionData[wIndex].Release();
	SectionData[wIndex] = Data;
	SectionHeaders[wIndex] = Header;
}

RELIB_EXPORT void PE::InsertSection(_In_ WORD wIndex, _In_ IMAGE_SECTION_HEADER Header, _In_opt_ Buffer* pData) {
	if (Status || wIndex > SectionHeaders.Size())
		return;

	// Insert
	SectionHeaders.Insert(wIndex, Header);
	if (pData) {
		SectionData.Insert(wIndex, *pData);
	} else {
		Buffer dud;
		SectionData.Insert(wIndex, dud);
	}
	NTHeaders.FileHeader.NumberOfSections++;
}

RELIB_EXPORT void PE::FixHeaders() {
	// DOS Header
	DosHeader.e_magic = IMAGE_DOS_SIGNATURE;
	DosHeader.e_lfanew = sizeof(IMAGE_DOS_HEADER) + DosStub.Size();

	// Set stuff
	uint64_t Raw = DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER) * NTHeaders.FileHeader.NumberOfSections;
	uint64_t RVA = Raw;
	IMAGE_SECTION_HEADER Header = { 0 };
	for (int i = 0; i < SectionHeaders.Size(); i++) {
		Raw += (Raw % NTHeaders.OptionalHeader.FileAlignment) ? (NTHeaders.OptionalHeader.FileAlignment - Raw % NTHeaders.OptionalHeader.FileAlignment) : 0;
		RVA += (RVA % NTHeaders.OptionalHeader.SectionAlignment) ? (NTHeaders.OptionalHeader.SectionAlignment - RVA % NTHeaders.OptionalHeader.SectionAlignment) : 0;
		Header = SectionHeaders[i];
		Header.PointerToRawData = Raw;
		Header.VirtualAddress = RVA;
		SectionHeaders[i] = Header;
		RVA += Header.Misc.VirtualSize;
		Raw += Header.SizeOfRawData;
	}

	// File header
	NTHeaders.OptionalHeader.Magic = 0x20B;
	NTHeaders.Signature = IMAGE_NT_SIGNATURE;
	NTHeaders.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
	NTHeaders.OptionalHeader.CheckSum = 0;
	NTHeaders.OptionalHeader.SizeOfImage = RVA;
	NTHeaders.OptionalHeader.SizeOfHeaders = DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER) * NTHeaders.FileHeader.NumberOfSections;
	NTHeaders.OptionalHeader.NumberOfRvaAndSizes = 0x10;
	NTHeaders.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
}

RELIB_EXPORT bool PE::ProduceBinary(_In_ HANDLE hFile) {
	// DOS Header
	if (!WriteFile(hFile, &DosHeader, sizeof(IMAGE_DOS_HEADER), NULL, NULL)) {
		return false;
	}

	// DOS stub
	if (DosStub.Data() && DosStub.Size() && !WriteFile(hFile, DosStub.Data(), DosStub.Size(), NULL, NULL)) {
		return false;
	}

	// NT Headers (skip DOS stub)
	if (!WriteFile(hFile, &NTHeaders, sizeof(IMAGE_NT_HEADERS64), NULL, NULL)) {
		return false;
	}

	// Section Headers
	if (!WriteFile(hFile, SectionHeaders.Data(), SectionHeaders.Size() * sizeof(IMAGE_SECTION_HEADER), NULL, NULL)) {
		return false;
	}

	// Section Data
	DWORD dwCurrentAddress = DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER) * NTHeaders.FileHeader.NumberOfSections;
	BYTE* pZeros = NULL;
	for (WORD i = 0; i < SectionHeaders.Size(); i++) {
		if (!SectionHeaders[i].PointerToRawData) continue;

		// Padding
		if (dwCurrentAddress < SectionHeaders[i].PointerToRawData) {
			pZeros = reinterpret_cast<BYTE*>(calloc(SectionHeaders[i].PointerToRawData - dwCurrentAddress, 1));
			if (!pZeros || !WriteFile(hFile, pZeros, SectionHeaders[i].PointerToRawData - dwCurrentAddress, NULL, NULL)) {
				if (pZeros) free(pZeros);
				return false;
			}
			free(pZeros);
			dwCurrentAddress += SectionHeaders[i].PointerToRawData - dwCurrentAddress;
		} else if (dwCurrentAddress > SectionHeaders[i].PointerToRawData) {
			return false;
		}
		
		// Write actual data (if any)
		if (SectionHeaders[i].SizeOfRawData) {
			if (SectionHeaders[i].SizeOfRawData < SectionData[i].Size() || !WriteFile(hFile, SectionData[i].Data(), SectionHeaders[i].SizeOfRawData, NULL, NULL)) {
				return false;
			}
			dwCurrentAddress += SectionHeaders[i].SizeOfRawData;
		}
	}

	// Overlay
	if (Overlay.Size() && Overlay.Data()) {
		if (!WriteFile(hFile, Overlay.Data(), Overlay.Size(), NULL, NULL)) return false;
	}

	return true;
}

RELIB_EXPORT bool PE::ProduceBinary(_In_ char* sName) {
	// Open file
	HANDLE hFile = CreateFileA(sName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE || !hFile) {
		return false;
	}

	bool bRet = ProduceBinary(hFile);

	// Close
	CloseHandle(hFile);
	return bRet;
}

RELIB_EXPORT Vector<DWORD> PE::GetExportedSymbolRVAs() {
	// Get export table
	Vector<DWORD> vec;
	if (!NTHeaders.OptionalHeader.DataDirectory[0].Size || !NTHeaders.OptionalHeader.DataDirectory[0].VirtualAddress) return vec;
	IMAGE_EXPORT_DIRECTORY ExportTable = ReadRVA<IMAGE_EXPORT_DIRECTORY>(NTHeaders.OptionalHeader.DataDirectory[0].VirtualAddress);
	if (!ExportTable.NumberOfFunctions || !ExportTable.AddressOfFunctions || !ExportTable.AddressOfNames) return vec;
	
	// Prepare data
	WORD wContainingSection = FindSectionByRVA(ExportTable.AddressOfFunctions);
	if (wContainingSection >= SectionHeaders.Size()) return vec;
	Buffer Data = SectionData[wContainingSection];
	if (!Data.Data() || !Data.Size() || SectionHeaders[wContainingSection].SizeOfRawData - (ExportTable.AddressOfFunctions - SectionHeaders[wContainingSection].VirtualAddress) < sizeof(DWORD) * ExportTable.NumberOfFunctions) return vec;
	DWORD offset = ExportTable.AddressOfFunctions - SectionHeaders[wContainingSection].VirtualAddress;

	// Copy data
	for (int i = 0; Data.Size() - offset >= sizeof(DWORD) && i < ExportTable.NumberOfFunctions; i++) {
		vec.Push(*(DWORD*)(Data.Data() + offset));
		offset += sizeof(DWORD);
	}
	return vec;
}

RELIB_EXPORT Vector<char*> PE::GetExportedSymbolNames() {
	// Get export table
	Vector<char*> vec;
	if (!NTHeaders.OptionalHeader.DataDirectory[0].Size || !NTHeaders.OptionalHeader.DataDirectory[0].VirtualAddress) return vec;
	IMAGE_EXPORT_DIRECTORY ExportTable = ReadRVA<IMAGE_EXPORT_DIRECTORY>(NTHeaders.OptionalHeader.DataDirectory[0].VirtualAddress);
	if (!ExportTable.NumberOfFunctions || !ExportTable.AddressOfFunctions || !ExportTable.AddressOfNames) return vec;

	// Prepare data
	WORD wContainingSection = FindSectionByRVA(ExportTable.AddressOfNames);
	if (wContainingSection >= SectionHeaders.Size()) return vec;
	Buffer Data = SectionData[wContainingSection];
	if (!Data.Data() || !Data.Size()) return vec;
	DWORD offset = ExportTable.AddressOfNames - SectionHeaders[wContainingSection].VirtualAddress;
	
	// Copy data
	for (int i = 0; Data.Size() - offset >= sizeof(DWORD) && i < ExportTable.NumberOfNames; i++) {
		vec.Push(ReadRVAString(*(DWORD*)(Data.Data() + offset)));
		offset += sizeof(DWORD);
	}
	return vec;
}

RELIB_EXPORT char* PE::ReadRVAString(_In_ DWORD dwRVA) {
	// Get string base
	WORD wIndex = FindSectionByRVA(dwRVA);
	if (wIndex >= SectionHeaders.Size() || !SectionData[wIndex].Data() || !SectionData[wIndex].Size()) return NULL;
	char* buf = reinterpret_cast<char*>(SectionData[wIndex].Data() + (dwRVA - SectionHeaders[wIndex].VirtualAddress));
	
	// Prevent out-of-bounds strings
	for (int i = 0; ; i++) {
		if (!buf[i]) return buf;
		if (i + (dwRVA - SectionHeaders[wIndex].VirtualAddress) >= SectionData[wIndex].Size()) break;
	}
	return NULL;
}

RELIB_EXPORT bool PE::WriteRVA(_In_ DWORD dwRVA, _In_ void* pData, _In_ size_t szData) {
	// Verify stuff
	WORD wSectionIndex = FindSectionByRVA(dwRVA);
	if (!pData || !szData || wSectionIndex > NTHeaders.FileHeader.NumberOfSections - 1 || !SectionHeaders[wSectionIndex].SizeOfRawData || SectionHeaders[wSectionIndex].VirtualAddress > dwRVA || SectionHeaders[wSectionIndex].VirtualAddress + SectionHeaders[wSectionIndex].SizeOfRawData < dwRVA + szData) {
		return false;
	}

	// Write data
	return !memcpy_s(SectionData[wSectionIndex].Data() + (dwRVA - SectionHeaders[wSectionIndex].VirtualAddress), SectionData[wSectionIndex].Size() - (dwRVA - SectionHeaders[wSectionIndex].VirtualAddress), pData, szData);
}

RELIB_EXPORT bool PE::ReadRVA(_In_ DWORD dwRVA, _Out_ void* pData, _In_ size_t szData) {
	WORD wSectionIndex = FindSectionByRVA(dwRVA);
	if (!pData || !szData || wSectionIndex > NTHeaders.FileHeader.NumberOfSections - 1 || !SectionHeaders[wSectionIndex].SizeOfRawData || SectionHeaders[wSectionIndex].VirtualAddress > dwRVA || SectionHeaders[wSectionIndex].VirtualAddress + SectionHeaders[wSectionIndex].SizeOfRawData < dwRVA + szData) {
		ZeroMemory(pData, szData);
		return false;
	}

	if (szData <= SectionData[wSectionIndex].Size() - (dwRVA - SectionHeaders[wSectionIndex].VirtualAddress)) {
		memcpy(pData, SectionData[wSectionIndex].Data() + (dwRVA - SectionHeaders[wSectionIndex].VirtualAddress), szData);
		return true;
	}
	return false;
}

RELIB_EXPORT Vector<DWORD> PE::GetRelocations() {
	Vector<DWORD> ret;
	if (Status || !NTHeaders.OptionalHeader.DataDirectory[5].Size || !NTHeaders.OptionalHeader.DataDirectory[5].VirtualAddress || NTHeaders.FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) return ret;
	
	WORD i = FindSectionByRVA(NTHeaders.OptionalHeader.DataDirectory[5].VirtualAddress);
	if (i >= SectionData.Size()) return ret;
	Buffer sec = SectionData[i];
	IMAGE_BASE_RELOCATION* pRelocation;
	size_t offset = NTHeaders.OptionalHeader.DataDirectory[5].VirtualAddress - SectionHeaders[i].VirtualAddress;

	if (sec.Data() && sec.Size() && sec.Size() - offset >= sizeof(IMAGE_DATA_DIRECTORY)) {
		WORD nOff = 0;

		do {
			pRelocation = reinterpret_cast<IMAGE_BASE_RELOCATION*>(sec.Data() + offset + nOff);
			if (!pRelocation->SizeOfBlock || !pRelocation->VirtualAddress) break;
			for (int j = 0, n = (pRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); j < n; j++) {
				if (sec.Size() - (offset + nOff + sizeof(IMAGE_BASE_RELOCATION) + sizeof(WORD) * j) < sizeof(WORD)) return ret;
				i = *reinterpret_cast<WORD*>(sec.Data() + offset + nOff + sizeof(IMAGE_BASE_RELOCATION) + sizeof(WORD) * j);
				if ((i & 0b1111000000000000) != 0b1010000000000000) continue;
				ret.Push(pRelocation->VirtualAddress + (i & 0b0000111111111111));
			}
			nOff += pRelocation->SizeOfBlock;
		} while (pRelocation->SizeOfBlock && NTHeaders.OptionalHeader.DataDirectory[5].Size > nOff && sec.Size() > offset + nOff && sec.Size() - offset - nOff >= sizeof(IMAGE_BASE_RELOCATION));
	}
	return ret;
}

RELIB_EXPORT void PE::DiscardOverlay() {
	OverlayOffset = 0;
	Overlay.Release();
}

RELIB_EXPORT DWORD PE::GetOverlayOffset() {
	return OverlayOffset;
}

RELIB_EXPORT Buffer GenerateRelocSection(_In_ Vector<DWORD> Relocations) {
	Buffer ret;
	ret.Allocate(sizeof(IMAGE_BASE_RELOCATION));
	IMAGE_BASE_RELOCATION* pReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(ret.Data());
	pReloc->SizeOfBlock = sizeof(IMAGE_BASE_RELOCATION);
	pReloc->VirtualAddress = 0;

	// If nothing needs to be relocated, generate NULL relocation
	if (!Relocations.Size())
		return ret;

	pReloc->VirtualAddress = Relocations[0] & ~0xFFF;
	QWORD RelocOff = 0;
	for (int i = 0; i < Relocations.Size(); i++) {
		// Generate new rva
		if (pReloc->VirtualAddress + 0x1000 <= Relocations[i]) {
			// Add pad
			if (ret.Size() % sizeof(DWORD)) {
				ret.Allocate(ret.Size() + sizeof(WORD));
				pReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(ret.Data() + RelocOff);
				pReloc->SizeOfBlock += sizeof(WORD);
				*reinterpret_cast<WORD*>(ret.Data() + ret.Size() - sizeof(WORD)) = 0;
			}

			// Create new thingymadoodle
			RelocOff = ret.Size();
			ret.Allocate(ret.Size() + sizeof(IMAGE_BASE_RELOCATION));
			pReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(ret.Data() + RelocOff);
			pReloc->SizeOfBlock = sizeof(IMAGE_BASE_RELOCATION);
			pReloc->VirtualAddress = Relocations[i] & ~0xFFF;
		}

		// Add entry
		ret.Allocate(ret.Size() + sizeof(WORD));
		pReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(ret.Data() + RelocOff);
		pReloc->SizeOfBlock += sizeof(WORD);
		*reinterpret_cast<WORD*>(ret.Data() + ret.Size() - sizeof(WORD)) = 0b1010000000000000 | ((Relocations[i] - pReloc->VirtualAddress) & 0xFFF);
	}

	// Add pad
	if (ret.Size() % sizeof(DWORD)) {
		ret.Allocate(ret.Size() + sizeof(WORD));
		pReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(ret.Data() + RelocOff);
		pReloc->SizeOfBlock += sizeof(WORD);
		*reinterpret_cast<WORD*>(ret.Data() + ret.Size() - sizeof(WORD)) = 0;
	}
	return ret;
}