/*!
 * @file asm.cpp
 * @author undisassemble
 * @brief Assembly related functions
 * @version 0.0.0
 * @date 2025-05-16
 * @copyright MIT License
 */

#define _RELIB_INTERNAL
#include "relib/asm.hpp"
#include "relib/asmtranslations.hpp"
using namespace x86;

typedef struct {
	BYTE Version : 3;
	BYTE Flags : 5;
	BYTE SizeProlog;
	BYTE NumUnwindCodes;
	BYTE FrameReg : 4;
	BYTE FrameRegOff : 4;
} UNWIND_INFO;

typedef struct {
	BYTE Offset;
	BYTE OpCode : 4;
	BYTE OpInfo : 4;
} UNWIND_CODE;

typedef struct {
	DWORD BeginAddress;
	DWORD EndAddress;
	DWORD HandlerAddress;
	DWORD JumpTarget;
} C_SCOPE_TABLE;

RELIB_EXPORT char* ZydisErrorToString(ZyanStatus Status) {
	switch (Status) {
	case ZYDIS_STATUS_NO_MORE_DATA:
		return "ZYDIS_STATUS_NO_MORE_DATA";
	case ZYDIS_STATUS_DECODING_ERROR:
		return "ZYDIS_STATUS_DECODING_ERROR";
	case ZYDIS_STATUS_INSTRUCTION_TOO_LONG:
		return "ZYDIS_STATUS_INSTRUCTION_TOO_LONG";
	case ZYDIS_STATUS_BAD_REGISTER:
		return "ZYDIS_STATUS_BAD_REGISTER";
	case ZYDIS_STATUS_ILLEGAL_LOCK:
		return "ZYDIS_STATUS_ILLEGAL_LOCK";
	case ZYDIS_STATUS_ILLEGAL_LEGACY_PFX:
		return "ZYDIS_STATUS_ILLEGAL_LEGACY_PFX";
	case ZYDIS_STATUS_ILLEGAL_REX:
		return "ZYDIS_STATUS_ILLEGAL_REX";
	case ZYDIS_STATUS_INVALID_MAP:
		return "ZYDIS_STATUS_INVALID_MAP";
	case ZYDIS_STATUS_MALFORMED_EVEX:
		return "ZYDIS_STATUS_MALFORMED_EVEX";
	case ZYDIS_STATUS_MALFORMED_MVEX:
		return "ZYDIS_STATUS_MALFORMED_MVEX";
	case ZYDIS_STATUS_INVALID_MASK:
		return "ZYDIS_STATUS_INVALID_MASK";
	case ZYDIS_STATUS_IMPOSSIBLE_INSTRUCTION:
		return "ZYDIS_STATUS_IMPOSSIBLE_INSTRUCTION";
	case ZYAN_STATUS_INVALID_ARGUMENT:
		return "ZYAN_STATUS_INVALID_ARGUMENT";
	default:
		return NULL;
	}
}

RELIB_EXPORT bool IsInstructionCF(_In_ ZydisMnemonic mnemonic) {
	switch (mnemonic) {
	case ZYDIS_MNEMONIC_JB:
	case ZYDIS_MNEMONIC_JBE:
	case ZYDIS_MNEMONIC_JCXZ:
	case ZYDIS_MNEMONIC_JECXZ:
	case ZYDIS_MNEMONIC_JKNZD:
	case ZYDIS_MNEMONIC_JKZD:
	case ZYDIS_MNEMONIC_JL:
	case ZYDIS_MNEMONIC_JLE:
	case ZYDIS_MNEMONIC_JMP:
	case ZYDIS_MNEMONIC_JNB:
	case ZYDIS_MNEMONIC_JNBE:
	case ZYDIS_MNEMONIC_JNL:
	case ZYDIS_MNEMONIC_JNLE:
	case ZYDIS_MNEMONIC_JNO:
	case ZYDIS_MNEMONIC_JNP:
	case ZYDIS_MNEMONIC_JNS:
	case ZYDIS_MNEMONIC_JNZ:
	case ZYDIS_MNEMONIC_JO:
	case ZYDIS_MNEMONIC_JP:
	case ZYDIS_MNEMONIC_JRCXZ:
	case ZYDIS_MNEMONIC_JS:
	case ZYDIS_MNEMONIC_JZ:
	case ZYDIS_MNEMONIC_LOOP:
	case ZYDIS_MNEMONIC_LOOPE:
	case ZYDIS_MNEMONIC_LOOPNE:
	case ZYDIS_MNEMONIC_CALL:
		return true;
	default:
		return false;
	}
}

RELIB_EXPORT bool IsInstructionMemory(_In_ DecodedInstruction* pInstruction, _In_ DecodedOperand* pOperand) {
	return IsInstructionCF(pInstruction->mnemonic) || pOperand->type == ZYDIS_OPERAND_TYPE_MEMORY;
}

RELIB_EXPORT void DecodedInstruction::operator=(_In_ ZydisDecodedInstruction instruction) {
	mnemonic = instruction.mnemonic;
	length = instruction.length;
	operand_count = instruction.operand_count_visible;
	attributes = instruction.attributes;
}

RELIB_EXPORT DecodedInstruction::operator ZydisDecodedInstruction() const {
	ZydisDecodedInstruction ret;
	ret.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
	ret.mnemonic = mnemonic;
	ret.length = length;
	ret.stack_width = 64;
	ret.operand_width = 64;
	ret.address_width = 64;
	ret.operand_count = operand_count;
	ret.operand_count_visible = operand_count;
	ret.attributes = attributes;
	return ret;
}

RELIB_EXPORT void DecodedOperand::operator=(_In_ ZydisDecodedOperand operand) {
	type = operand.type;
	size = operand.size;
	switch (type) {
	case ZYDIS_OPERAND_TYPE_REGISTER:
		reg = operand.reg;
		break;
	case ZYDIS_OPERAND_TYPE_MEMORY:
		mem = operand.mem;
		break;
	case ZYDIS_OPERAND_TYPE_IMMEDIATE:
		imm.is_signed = operand.imm.is_signed;
		imm.value.u = operand.imm.value.u;
		break;
	case ZYDIS_OPERAND_TYPE_POINTER:
		ReLibData.WarningCallback("I don\'t know if this works, operand.ptr.segment = %d\n", operand.ptr.segment);
		mem.segment = (ZydisRegister)operand.ptr.segment;
		mem.base = ZYDIS_REGISTER_NONE;
		mem.index = ZYDIS_REGISTER_NONE;
		mem.scale = 0;
		mem.disp.has_displacement = true;
		mem.disp.value = operand.ptr.offset;
	}
}

RELIB_EXPORT DecodedOperand::operator ZydisDecodedOperand() const {
	ZydisDecodedOperand ret;
	ret.type = type;
	ret.size = size;
	switch (type) {
	case ZYDIS_OPERAND_TYPE_REGISTER:
		ret.reg = reg;
		break;
	case ZYDIS_OPERAND_TYPE_MEMORY:
		ret.mem = mem;
		break;
	case ZYDIS_OPERAND_TYPE_IMMEDIATE:
		ret.imm.is_signed = imm.is_signed;
		ret.imm.value.u = imm.value.u;
		break;
	case ZYDIS_OPERAND_TYPE_POINTER:
		ret.ptr.offset = mem.disp.value;
		ret.ptr.segment = mem.segment;
	}
	return ret;
}

RELIB_EXPORT Asm::Asm() : PE() {}

RELIB_EXPORT Asm::Asm(_In_ char* sFileName) : PE(sFileName) {
	if (Status) return;
	ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
	Vector<Line> lines;
	lines.bExponentialGrowth = true;
	AsmSection sec = { 0 };
	for (int i = 0; i < SectionHeaders.Size(); i++) {
		sec.Lines = reinterpret_cast<Vector<Line>*>(malloc(sizeof(Vector<Line>)));
		memcpy(sec.Lines, &lines, sizeof(Vector<Line>));
		sec.OldRVA = SectionHeaders[i].VirtualAddress;
		sec.OldSize = SectionHeaders[i].Misc.VirtualSize;
		Sections.Push(sec);
	}
}

RELIB_EXPORT Asm::Asm(_In_ HANDLE hFile) : PE(hFile) {
	ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
	Vector<Line> lines;
	lines.bExponentialGrowth = true;
	AsmSection sec = { 0 };
	for (int i = 0; i < SectionHeaders.Size(); i++) {
		sec.Lines = reinterpret_cast<Vector<Line>*>(malloc(sizeof(Vector<Line>)));
		memcpy(sec.Lines, &lines, sizeof(Vector<Line>));
		sec.NewRVA = sec.OldRVA = SectionHeaders[i].VirtualAddress;
		sec.OldSize = SectionHeaders[i].Misc.VirtualSize;
		Sections.Push(sec);
	}
}

RELIB_EXPORT Asm::~Asm() {
	for (int i = 0; i < Sections.Size(); i++) if (Sections[i].Lines) {
		Sections[i].Lines->Release();
		free(Sections[i].Lines);
	}
	Sections.Release();
	JumpTables.Release();
	FunctionRanges.Release();
}

RELIB_EXPORT void Asm::SetAssembler(_In_ asmjit::x86::Assembler* pAssembler) {
	pAsm = pAssembler;
}

RELIB_EXPORT DWORD Asm::GetNextOriginal(_In_ DWORD dwSec, _In_ DWORD dwIndex) {
	Vector<Line>* Lines = Sections[dwSec].Lines;
	if (!Lines || Lines->Size() <= dwIndex) return _UI32_MAX;
	
	for (; dwIndex < Lines->Size(); dwIndex++) {
		if (Lines->At(dwIndex).OldRVA) return dwIndex;
	}

	return _UI32_MAX;
}

RELIB_EXPORT DWORD Asm::GetPrevOriginal(_In_ DWORD dwSec, _In_ DWORD dwIndex) {
	Vector<Line>* Lines = Sections[dwSec].Lines;
	if (!Lines) return _UI32_MAX;

	for (;; dwIndex--) {
		if (Lines->At(dwIndex).OldRVA) return dwIndex;
		if (!dwIndex) return _UI32_MAX;
	}

	return _UI32_MAX;
}

RELIB_EXPORT DWORD Asm::FindSectionIndex(_In_ DWORD dwRVA) {
	for (DWORD i = 0; i < Sections.Size(); i++) {
		if (Sections[i].OldRVA <= dwRVA && Sections[i].OldRVA + Sections[i].OldSize >= dwRVA) {
			return i;
		}
	}
	return _UI32_MAX;
}

RELIB_EXPORT DWORD Asm::FindIndex(_In_ DWORD dwSec, _In_ DWORD dwRVA) {
	if (dwSec > Sections.Size()) return _UI32_MAX;
	Vector<Line>* Lines = Sections[dwSec].Lines;

	// If no lines exist, it will just be the first line
	if (!Lines || !Lines->Size())
		return _UI32_MAX;

	// Check bounds
	if (Lines->At(0).OldRVA && dwRVA >= Lines->At(0).OldRVA && dwRVA < Lines->At(0).OldRVA + GetLineSize(Lines->At(0)))
		return 0;
	if (Lines->At(Lines->Size() - 1).OldRVA && dwRVA >= Lines->At(Lines->Size() - 1).OldRVA && dwRVA < Lines->At(Lines->Size() - 1).OldRVA + GetLineSize(Lines->At(Lines->Size() - 1)))
		return Lines->Size() - 1;

	if (Lines->Size() == 1)
		return _UI32_MAX;

	// Search
	size_t szMin = 0, szMax = Lines->Size(), i = 0;
	size_t PrevI = 0;
	while (szMin <= szMax) {
		i = szMin + (szMax - szMin) * 0.5;

		if (szMin + 1 == szMax) {
			i = szMin = szMax;
		}
		i = GetNextOriginal(dwSec, i);
		if (i >= szMax || i == PrevI) i = GetNextOriginal(dwSec, szMin + 1);
		if (i == PrevI) break;

		// Check index
		if (dwRVA >= Lines->At(i).OldRVA && dwRVA < Lines->At(i).OldRVA + GetLineSize(Lines->At(i))) {
			return i;
		}

		if (dwRVA >= Lines->At(i).OldRVA + GetLineSize(Lines->At(i))) {
			// Shift range
			szMin = i;
		}

		else if (dwRVA < Lines->At(i).OldRVA) {
			// Shift range
			szMax = i;
		}

		else {
			return _UI32_MAX;
		}
		PrevI = i;
	}

	return _UI32_MAX;
}

RELIB_EXPORT DWORD Asm::FindPosition(_In_ DWORD dwSec, _In_ DWORD dwRVA) {
	Vector<Line>* Lines = Sections[dwSec].Lines;

	// If no lines exist, it will just be the first line
	if (!Lines->Size())
		return 0;

	// Check bounds
	if (Lines->At(0).OldRVA && dwRVA < Lines->At(0).OldRVA)
		return 0;
	else if (Lines->At(0).OldRVA && dwRVA == Lines->At(0).OldRVA)
		return _UI32_MAX - 1;
	if (Lines->At(Lines->Size() - 1).OldRVA && dwRVA >= Lines->At(Lines->Size() - 1).OldRVA + GetLineSize(Lines->At(Lines->Size() - 1)))
		return Lines->Size();
	else if (Lines->At(Lines->Size() - 1).OldRVA && dwRVA == Lines->At(Lines->Size() - 1).OldRVA)
		return _UI32_MAX - 1;

	// Search
	size_t szMin = 0, szMax = Lines->Size(), i = 0;
	while (szMin < szMax) {
		i = szMin + (szMax - szMin) * 0.5;

		i = GetNextOriginal(dwSec, i);
		if (i == _UI32_MAX) break;

		if (dwRVA >= Lines->At(i).OldRVA + GetLineSize(Lines->At(i))) {
			// In between
			if (dwRVA < Lines->At(GetNextOriginal(dwSec, i + 1)).OldRVA) {
				return GetNextOriginal(dwSec, i + 1);
			}

			// Shift range
			szMin = i;
		}

		else if (dwRVA < Lines->At(i).OldRVA) {
			// In between
			if (dwRVA > Lines->At(GetPrevOriginal(dwSec, i - 1)).OldRVA + GetLineSize(Lines->At(GetPrevOriginal(dwSec, i - 1)))) {
				return i;
			}

			// Shift range
			szMax = i;
		}
		
		else {
			return _UI32_MAX - 1;
		}
	}

	return _UI32_MAX;
}

RELIB_EXPORT bool Asm::DisasmRecursive(_In_ DWORD dwRVA) {
	Vector<DWORD> ToDisasm; // To prevent stack overflows on big programs, this function is a lie and is not actually recursive, sue me
	ToDisasm.Push(dwRVA);
	ZydisDecodedInstruction Instruction;
	ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];
	Vector<Line>* Lines;
	Vector<Line> TempLines;
	TempLines.bExponentialGrowth = true;
	DWORD SectionIndex;
#ifdef ENABLE_DUMPING
	char FormattedBuf[128];
	ZydisFormatter Formatter;
	ZydisFormatterInit(&Formatter, ZYDIS_FORMATTER_STYLE_INTEL);
#endif

	do {
		// Setup
		dwRVA = ToDisasm.Pop();
		TempLines.Release();
		if (!dwRVA) {
			ReLibData.WarningCallback("Skipping NULL RVA\n");
			continue;
		}
		SectionIndex = FindSectionIndex(dwRVA);
		if (SectionIndex > Sections.Size()) {
			ReLibData.ErrorCallback("Failed to find index of section at 0x%p\n", NTHeaders.OptionalHeader.ImageBase + dwRVA);
			return false;
		}
		Lines = Sections[SectionIndex].Lines;
		Buffer RawBytes = { 0 };
		{
			RawBytes = SectionData[FindSectionByRVA(dwRVA)];
			IMAGE_SECTION_HEADER Header = SectionHeaders[FindSectionByRVA(dwRVA)];
			if (!RawBytes.pBytes || !RawBytes.u64Size || !Header.Misc.VirtualSize) {
				ReLibData.WarningCallback("Failed to get bytes at 0x%p\n", NTHeaders.OptionalHeader.ImageBase + dwRVA);
				continue;
			}
			RawBytes.pBytes += dwRVA - Header.VirtualAddress;
			RawBytes.u64Size -= dwRVA - Header.VirtualAddress;
		}

		// Locate current position in index
		DWORD i = FindPosition(SectionIndex, dwRVA);
		if (i > Lines->Size()) {
			if (i == _UI32_MAX - 1) continue; // Already disassembled
			ReLibData.ErrorCallback("Failed to find position for instruction at 0x%p\n", NTHeaders.OptionalHeader.ImageBase + dwRVA);
			return false;
		}

		// Start disassembling
		Line CraftedLine;
		CraftedLine.Type = Decoded;
		while (RawBytes.u64Size && ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, RawBytes.pBytes, RawBytes.u64Size, &Instruction, Operands))) {
			// Convert
			CraftedLine.Decoded.Instruction = Instruction;
			for (int i = 0; i < CraftedLine.Decoded.Instruction.operand_count; i++) {
				CraftedLine.Decoded.Operands[i] = Operands[i];
			}
			CraftedLine.OldRVA = dwRVA;
			if (IsInstructionCF(Instruction.mnemonic)) {
				if (Operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER && ZYAN_FAILED(ZydisCalcAbsoluteAddress(&Instruction, Operands, CraftedLine.OldRVA, &CraftedLine.Decoded.refs))) {
					ReLibData.WarningCallback("Could not calculate referenced address (0x%p) (type 1)\n", NTHeaders.OptionalHeader.ImageBase + dwRVA);
				}
			} else {
				for (int i = 0; i < Instruction.operand_count_visible; i++) {
					if (Operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY && Operands[i].mem.base == ZYDIS_REGISTER_RIP) {
						if (ZYAN_FAILED(ZydisCalcAbsoluteAddress(&Instruction, &Operands[i], CraftedLine.OldRVA, &CraftedLine.Decoded.refs))) {
							ReLibData.WarningCallback("Could not calculate referenced address (0x%p) (type 2)\n", NTHeaders.OptionalHeader.ImageBase + dwRVA);
						}
						break;
					}
				}
			}

			// Edit progress
			Progress += Instruction.length;
			fProgress = (float)Progress / (float)ToDo;

			TempLines.Push(CraftedLine);

			if (CraftedLine.Decoded.Instruction.mnemonic == ZYDIS_MNEMONIC_RET) break;

			// Check if is jump table
			if (CraftedLine.Decoded.Instruction.mnemonic == ZYDIS_MNEMONIC_LEA && CraftedLine.Decoded.Operands[1].mem.base == ZYDIS_REGISTER_RIP) {
				DWORD trva = 0, rva = 0, disp = 0, odisp = 0;
				{
					uint64_t r;
					ZydisCalcAbsoluteAddress(&Instruction, &Operands[1], CraftedLine.OldRVA, &r);
					disp = odisp = r;
				}

				do {
					rva = ReadRVA<DWORD>(disp);
					if (!rva) break;
					trva = odisp + rva;
					if (!(trva != 0xCCCCCCCC && trva >= Sections[SectionIndex].OldRVA && trva < Sections[SectionIndex].OldRVA + Sections[SectionIndex].OldSize)) break;
					if (!JumpTables.Includes(trva)) JumpTables.Push(trva);
					Line TempJumpTable;
					TempJumpTable.OldRVA = disp;
					TempJumpTable.Type = JumpTable;
					TempJumpTable.bRelative = true;
					TempJumpTable.JumpTable.Value = rva;
					TempJumpTable.JumpTable.Base = odisp;
					WORD SecIndex = FindSectionIndex(disp);
					DWORD i = FindPosition(SecIndex, disp);
					if (i == _UI32_MAX) {
						ReLibData.ErrorCallback("Failed to find position for 0x%p\n", NTHeaders.OptionalHeader.ImageBase + disp);
						return false;
					}
					if (i != _UI32_MAX - 1) Sections[SecIndex].Lines->Insert(i, TempJumpTable);
					disp += sizeof(DWORD);
				} while (1);
			}
			if (CraftedLine.Decoded.Instruction.mnemonic == ZYDIS_MNEMONIC_MOV && CraftedLine.Decoded.Operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && CraftedLine.Decoded.Operands[1].mem.scale == 4 && CraftedLine.Decoded.Operands[1].mem.base != ZYDIS_REGISTER_RIP) {
				DWORD rva = 0;
				DWORD disp = CraftedLine.Decoded.Operands[1].mem.disp.value;
				while ((rva = ReadRVA<DWORD>(disp)) != 0xCCCCCCCC && rva >= Sections[SectionIndex].OldRVA && rva < Sections[SectionIndex].OldRVA + Sections[SectionIndex].OldSize) {
					if (!JumpTables.Includes(rva)) JumpTables.Push(rva);
					Line TempJumpTable;
					TempJumpTable.OldRVA = disp;
					TempJumpTable.Type = JumpTable;
					TempJumpTable.JumpTable.Value = rva;
					WORD SecIndex = FindSectionIndex(disp);
					DWORD i = FindPosition(SecIndex, disp);
					if (i == _UI32_MAX) {
						ReLibData.ErrorCallback("Failed to find position for 0x%p\n", NTHeaders.OptionalHeader.ImageBase + disp);
						return false;
					}
					if (i != _UI32_MAX - 1) Sections[SecIndex].Lines->Insert(i, TempJumpTable);
					disp += sizeof(DWORD);
				}
			}
 
			if (IsInstructionCF(CraftedLine.Decoded.Instruction.mnemonic)) {
				// Calculate absolute address
				if (!((CraftedLine.Decoded.Operands[0].type != ZYDIS_OPERAND_TYPE_MEMORY && CraftedLine.Decoded.Operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) || (CraftedLine.Decoded.Operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && (CraftedLine.Decoded.Operands[0].mem.base != ZYDIS_REGISTER_RIP && CraftedLine.Decoded.Operands[0].mem.base != ZYDIS_REGISTER_NONE)))) {
					uint64_t u64Referencing;
					if (ZYAN_FAILED(ZydisCalcAbsoluteAddress(&Instruction, &Operands[0], CraftedLine.OldRVA, &u64Referencing))) {
						ReLibData.ErrorCallback("Failed to disassemble instruction at 0x%p\n", NTHeaders.OptionalHeader.ImageBase + CraftedLine.OldRVA);
						TempLines.Release();
						return false;
					}

					// If address is a pointer, use the address stored at that address (if possible)
					if (CraftedLine.Decoded.Operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
						// If address is an import we dont want to disassemble it
						IMAGE_DATA_DIRECTORY ImportDir = NTHeaders.OptionalHeader.DataDirectory[1];
						if (u64Referencing >= ImportDir.VirtualAddress && u64Referencing < (uint64_t)ImportDir.VirtualAddress + ImportDir.Size) {
							u64Referencing = 0;
						}

						// Find the section (u64Referencing is absolute, not an RVA, so we have to translate it manually)
						else {
							WORD wContainingIndex = FindSectionByRVA(u64Referencing);
							if (wContainingIndex >= SectionHeaders.Size()) {
								ReLibData.ErrorCallback("Failed to disassemble code pointed to at 0x%p\n", NTHeaders.OptionalHeader.ImageBase + u64Referencing);
								TempLines.Release();
								return false;
							}
							
							// Extract the address
							Line insert;
							insert.OldRVA = u64Referencing;
							u64Referencing = ReadRVA<uint64_t>(u64Referencing);
							if (!u64Referencing) {
								ReLibData.WarningCallback("Failed to retrieve address at 0x%p\n", u64Referencing);
								u64Referencing = 0;
							}
							
							// Insert address
							insert.Type = Pointer;
							insert.Pointer.IsAbs = true;
							insert.Pointer.Abs = u64Referencing;
							{
								WORD wInsertAt = FindPosition(wContainingIndex, insert.OldRVA);
								if (wInsertAt == _UI16_MAX) {
									ReLibData.WarningCallback("Failed to find position to insert line at 0x%p\n", NTHeaders.OptionalHeader.ImageBase + insert.OldRVA);
								} else if (wInsertAt != _UI16_MAX - 1) {
									Sections[wContainingIndex].Lines->Insert(wInsertAt, insert);
								}
							}

							u64Referencing -= NTHeaders.OptionalHeader.ImageBase;
						}
					}

					if (u64Referencing) {
						// Disassemble the address (if good)
						IMAGE_SECTION_HEADER Header = SectionHeaders[FindSectionByRVA(u64Referencing)];
						if (Header.Characteristics & IMAGE_SCN_MEM_EXECUTE && Header.SizeOfRawData > u64Referencing - Header.VirtualAddress) {
							if (!ToDisasm.Includes(u64Referencing)) {
								ToDisasm.Push(u64Referencing);
								if (CraftedLine.Decoded.Instruction.mnemonic == ZYDIS_MNEMONIC_CALL && !Functions.Includes(u64Referencing)) {
									Functions.Push(u64Referencing);
								}
							}
						}

						// Exit if unconditional
						if (CraftedLine.Decoded.Instruction.mnemonic == ZYDIS_MNEMONIC_JMP) {
							break;
						}
					}
				}
			}

			// Adjust vars
			dwRVA += CraftedLine.Decoded.Instruction.length;
			RawBytes.u64Size -= CraftedLine.Decoded.Instruction.length;
			RawBytes.pBytes += CraftedLine.Decoded.Instruction.length;

			// Stop disassembly if the next instruction has already been disassembled
			if (i < Lines->Size() && Lines->At(i).OldRVA == dwRVA) {
				break;
			}
		}

		// Insert lines
		Lines->Insert(i, TempLines);
	} while (ToDisasm.Size());

	ToDisasm.Release();
	return true;
}

RELIB_EXPORT bool Asm::CheckRuntimeFunction(_In_ RUNTIME_FUNCTION* pFunc, _In_ bool bFixAddr) {
	// Fix addresses mode
	if (bFixAddr) {
		pFunc->BeginAddress = TranslateOldAddress(pFunc->BeginAddress);
		pFunc->EndAddress = TranslateOldAddress(pFunc->EndAddress);
		pFunc->UnwindData = TranslateOldAddress(pFunc->UnwindData);
	} else {
		if (!Functions.Includes(pFunc->BeginAddress)) Functions.Push(pFunc->BeginAddress);
		// Disassemble
		if (pFunc->BeginAddress && !DisasmRecursive(pFunc->BeginAddress))
			return false;
	}

	// Check unwind info for function
	UNWIND_INFO UnwindInfo = ReadRVA<UNWIND_INFO>(pFunc->UnwindData);
	if (UnwindInfo.NumUnwindCodes & 1) UnwindInfo.NumUnwindCodes++;

	// Check for handler
	if (UnwindInfo.Flags & UNW_FLAG_EHANDLER || UnwindInfo.Flags & UNW_FLAG_UHANDLER) {
		
		// Handler RVA
		DWORD RVA = ReadRVA<DWORD>(pFunc->UnwindData + sizeof(UNWIND_INFO) + UnwindInfo.NumUnwindCodes * sizeof(UNWIND_CODE));
		
		// Scope table
		Vector<C_SCOPE_TABLE> Tables;
		Tables.nItems = ReadRVA<DWORD>(pFunc->UnwindData + sizeof(UNWIND_INFO) + UnwindInfo.NumUnwindCodes * sizeof(UNWIND_CODE) + sizeof(DWORD));
		if (Tables.nItems > 10) {
			ReLibData.WarningCallback("Exception handler at 0x%p had more than 10 tables, skipping\n", NTHeaders.OptionalHeader.ImageBase + pFunc->UnwindData);
			return true;
		}
		Tables.Grow();
		ReLibData.LoggingCallback("Processing exception exception handler with %lu table(s) (at 0x%p)\n", Tables.nItems, NTHeaders.OptionalHeader.ImageBase + pFunc->UnwindData);
		for (int i = 0; i < Tables.nItems; i++) {
			Tables[i] = ReadRVA<C_SCOPE_TABLE>(pFunc->UnwindData + sizeof(UNWIND_INFO) + UnwindInfo.NumUnwindCodes * sizeof(UNWIND_CODE) + sizeof(DWORD) * 2 + sizeof(C_SCOPE_TABLE) * i);
		}

		if (bFixAddr) {
			WriteRVA<DWORD>(pFunc->UnwindData + sizeof(UNWIND_INFO) + UnwindInfo.NumUnwindCodes * sizeof(UNWIND_CODE), TranslateOldAddress(RVA));
			
			// Scope table
			for (int i = 0; i < Tables.Size(); i++) {
				C_SCOPE_TABLE t = Tables[i];
				t.BeginAddress = TranslateOldAddress(Tables[i].BeginAddress);
				t.EndAddress = TranslateOldAddress(Tables[i].EndAddress);
				t.HandlerAddress = TranslateOldAddress(Tables[i].HandlerAddress);
				t.JumpTarget = TranslateOldAddress(Tables[i].JumpTarget);
				WriteRVA<C_SCOPE_TABLE>(pFunc->UnwindData + sizeof(UNWIND_INFO) + UnwindInfo.NumUnwindCodes * sizeof(UNWIND_CODE) + sizeof(DWORD) * 2 + sizeof(C_SCOPE_TABLE) * i, t);
			}
		} else {
			if (RVA && !DisasmRecursive(RVA)) return false;
			
			// Scope table
			for (int i = 0; i < Tables.Size(); i++) {
				if (Tables[i].BeginAddress && !DisasmRecursive(Tables[i].BeginAddress)) return false;
				if (Tables[i].EndAddress && !DisasmRecursive(Tables[i].EndAddress)) return false;
				if (Tables[i].HandlerAddress && !DisasmRecursive(Tables[i].HandlerAddress)) return false;
				if (Tables[i].JumpTarget && !DisasmRecursive(Tables[i].JumpTarget)) return false;
			}
		}
		Tables.Release();
	}
	return true;
}

RELIB_EXPORT bool Asm::Disassemble() {
	if (Status) {
		ReLibData.ErrorCallback("Could not begin disassembly, as no binary is loaded (%hhd)\n", Status);
		return false;
	}

	// Calculate estimated size to disassemble
	for (int i = 0; i < NTHeaders.FileHeader.NumberOfSections; i++) {
		if (SectionHeaders[i].Characteristics & IMAGE_SCN_CNT_CODE || SectionHeaders[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			ToDo += SectionHeaders[i].SizeOfRawData;
		}
	}

	ReLibData.LoggingCallback("Beginning disassembly\n");

	// Insert known absolutes
	Vector<DWORD> relocs = GetRelocations();
	for (int i = 0; i < relocs.Size(); i++) {
		Line insert;
		insert.OldRVA = relocs[i];
		insert.Type = Pointer;
		insert.Pointer.IsAbs = true;
		insert.Pointer.Abs = ReadRVA<uint64_t>(insert.OldRVA);
		WORD wContainingSec = FindSectionIndex(insert.OldRVA);
		WORD wIndex = FindPosition(wContainingSec, insert.OldRVA);
		if (wIndex == _UI16_MAX || wContainingSec == _UI16_MAX) {
			ReLibData.WarningCallback("Failed to find position to insert line at 0x%p\n", NTHeaders.OptionalHeader.ImageBase + insert.OldRVA);
			continue;
		}
		Sections[wContainingSec].Lines->Insert(wIndex, insert);
	}

	// Insert known RVAs
	{
		Line insert;
		insert.Type = Pointer;
		insert.Pointer.IsAbs = false;

		// IAT
		if (NTHeaders.OptionalHeader.DataDirectory[1].VirtualAddress && NTHeaders.OptionalHeader.DataDirectory[1].Size) {
			// Insert entries
			IAT_ENTRY entry = { 0 };
			insert.OldRVA = NTHeaders.OptionalHeader.DataDirectory[1].VirtualAddress;
			DWORD wSecIndex = FindSectionIndex(insert.OldRVA);
			DWORD wIndex = FindPosition(wSecIndex, insert.OldRVA);
			if (wIndex == _UI32_MAX || wSecIndex == _UI32_MAX) {
				ReLibData.ErrorCallback("Failed to insert IAT!\n");
				return false;
			}
			do {
				entry = ReadRVA<IAT_ENTRY>(insert.OldRVA);
				if (!entry.LookupRVA || !entry.NameRVA) break;
				insert.Pointer.RVA = entry.LookupRVA;
				Sections[wSecIndex].Lines->Insert(wIndex, insert);
				wIndex++;
				insert.OldRVA += sizeof(DWORD) * 3;
				insert.Pointer.RVA = entry.NameRVA;
				Sections[wSecIndex].Lines->Insert(wIndex, insert);
				wIndex++;
				insert.OldRVA += sizeof(DWORD);
				insert.Pointer.RVA = entry.ThunkRVA;
				Sections[wSecIndex].Lines->Insert(wIndex, insert);
				wIndex++;
				insert.OldRVA += sizeof(DWORD);
			} while (entry.LookupRVA && entry.NameRVA);
			
			// Insert names
			IAT_ENTRY* pEntries = GetIAT();
			for (int i = 0; pEntries && pEntries[i].LookupRVA; i++) {
				// Begin
				insert.OldRVA = pEntries[i].LookupRVA;
				DWORD wSecIndex = FindSectionIndex(insert.OldRVA);
				DWORD wIndex = FindPosition(wSecIndex, insert.OldRVA);
				if (wIndex == _UI32_MAX || wSecIndex == _UI32_MAX) {
					ReLibData.ErrorCallback("Failed to insert IAT!\n");
					return false;
				}
				if (wIndex == _UI32_MAX - 1) {
					continue;
				}

				// Do
				do {
					insert.Pointer.RVA = ReadRVA<DWORD>(insert.OldRVA);
					if (!insert.Pointer.RVA) break;
					Sections[wSecIndex].Lines->Insert(wIndex, insert);
					wIndex++;
					insert.OldRVA += sizeof(uint64_t);
				} while (insert.Pointer.RVA);
			}
		}

		// Exports
		if (NTHeaders.OptionalHeader.DataDirectory[0].VirtualAddress && NTHeaders.OptionalHeader.DataDirectory[0].Size) {
			IMAGE_EXPORT_DIRECTORY ExportTable = ReadRVA<IMAGE_EXPORT_DIRECTORY>(NTHeaders.OptionalHeader.DataDirectory[0].VirtualAddress);
			insert.OldRVA = NTHeaders.OptionalHeader.DataDirectory[0].VirtualAddress + sizeof(DWORD) * 7;
			DWORD wSecIndex = FindSectionIndex(insert.OldRVA);
			DWORD wIndex = FindPosition(wSecIndex, insert.OldRVA);
			if (wIndex == _UI32_MAX || wSecIndex == _UI32_MAX) {
				ReLibData.ErrorCallback("Failed to insert exports!\n");
				return false;
			}
			insert.Pointer.RVA = ExportTable.AddressOfFunctions;
			Sections[wSecIndex].Lines->Insert(wIndex, insert);
			wIndex++;
			insert.OldRVA += sizeof(DWORD);
			insert.Pointer.RVA = ExportTable.AddressOfNames;
			Sections[wSecIndex].Lines->Insert(wIndex, insert);
			wIndex++;
			insert.OldRVA += sizeof(DWORD);
			insert.Pointer.RVA = ExportTable.AddressOfNameOrdinals;
			Sections[wSecIndex].Lines->Insert(wIndex, insert);

			// Functions
			insert.OldRVA = ExportTable.AddressOfFunctions;
			wSecIndex = FindSectionIndex(insert.OldRVA);
			wIndex = FindPosition(wSecIndex, insert.OldRVA);
			if (wIndex == _UI32_MAX || wSecIndex == _UI32_MAX) {
				ReLibData.ErrorCallback("Failed to insert exports!\n");
				return false;
			}
			for (int i = 0; i < ExportTable.NumberOfFunctions; i++) {
				insert.Pointer.RVA = ReadRVA<DWORD>(insert.OldRVA);
				Sections[wSecIndex].Lines->Insert(wIndex, insert);
				wIndex++;
				insert.OldRVA += sizeof(DWORD);
			}

			// Names
			insert.OldRVA = ExportTable.AddressOfNames;
			wSecIndex = FindSectionIndex(insert.OldRVA);
			wIndex = FindPosition(wSecIndex, insert.OldRVA);
			if (wIndex == _UI32_MAX || wSecIndex == _UI32_MAX) {
				ReLibData.ErrorCallback("Failed to insert exports!\n");
				return false;
			}
			for (int i = 0; i < ExportTable.NumberOfNames; i++) {
				insert.Pointer.RVA = ReadRVA<DWORD>(insert.OldRVA);
				Sections[wSecIndex].Lines->Insert(wIndex, insert);
				wIndex++;
				insert.OldRVA += sizeof(DWORD);
			}
		}
	}

	// Initialize Zydis
	ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

	// Disassemble entry point
	if (!DisasmRecursive(NTHeaders.OptionalHeader.AddressOfEntryPoint)) {
		return false;
	}
	ReLibData.LoggingCallback("Disassembled Entry Point (0x%p)\n", NTHeaders.OptionalHeader.ImageBase + NTHeaders.OptionalHeader.AddressOfEntryPoint);

	// Error check (TEMPORARY)
#ifdef _DEBUG
	{
		Vector<Line>* Lines = Sections[FindSectionIndex(NTHeaders.OptionalHeader.AddressOfEntryPoint)].Lines;
		for (size_t i = 0; i < Lines->Size() - 1; i++) {
			if (Lines->At(i).OldRVA + GetLineSize(Lines->At(i)) > Lines->At(i + 1).OldRVA) {
				ReLibData.ErrorCallback("Peepee poopoo (0x%p + %u -> 0x%p)\n", NTHeaders.OptionalHeader.ImageBase + Lines->At(i).OldRVA, GetLineSize(Lines->At(i)), NTHeaders.OptionalHeader.ImageBase + Lines->At(i + 1).OldRVA);
				return false;
			}
		}
	}
#endif

	// Disassemble TLS callbacks
	uint64_t* pCallbacks = GetTLSCallbacks();
	if (pCallbacks) {
		for (WORD i = 0; pCallbacks[i]; i++) {
			if (!DisasmRecursive(pCallbacks[i] - NTHeaders.OptionalHeader.ImageBase)) {
				return false;
			}
			ReLibData.LoggingCallback("Disassembled TLS Callback (0x%p)\n", pCallbacks[i]);
		}
	}

	// Disassemble exports
	{
		Vector<DWORD> Exports = GetExportedSymbolRVAs();
		Vector<char*> ExportNames = GetExportedSymbolNames();
		for (int i = 0; i < Exports.Size(); i++) {
			if (!DisasmRecursive(Exports[i])) {
				return false;
			}
			ReLibData.LoggingCallback("Disassembled exported function \'%s\'\n", ExportNames[i]);
		}
	}
	ReLibData.LoggingCallback("Disassembled Exports\n");

	// Disassemble exception dir
	IMAGE_DATA_DIRECTORY ExcDataDir = NTHeaders.OptionalHeader.DataDirectory[3];
	if (ExcDataDir.VirtualAddress) {
		Buffer ExcData = SectionData[FindSectionByRVA(ExcDataDir.VirtualAddress)];
		IMAGE_SECTION_HEADER ExcSecHeader = SectionHeaders[FindSectionByRVA(ExcDataDir.VirtualAddress)];
		if (ExcData.pBytes && ExcSecHeader.VirtualAddress) {
			RUNTIME_FUNCTION* pArray = reinterpret_cast<RUNTIME_FUNCTION*>(ExcData.pBytes + ExcDataDir.VirtualAddress - ExcSecHeader.VirtualAddress);
			for (uint32_t i = 0, n = ExcDataDir.Size / sizeof(RUNTIME_FUNCTION); i < n; i++) {
				if (!CheckRuntimeFunction(&pArray[i])) {
					return false;
				}
			}
		}
	}
	ReLibData.LoggingCallback("Disassembled Exception Directory\n");

	// Disassemble jump tables
	{
		DWORD osize = JumpTables.Size();
		while (JumpTables.Size()) {
			if (!DisasmRecursive(JumpTables.Pop()))
				return false;
		}
		if (osize) ReLibData.LoggingCallback("Disassembled %d switch cases\n", osize);
	}

	ReLibData.LoggingCallback("Finished disassembly\n");

	// Insert missing data + padding
	Line line;
	ReLibData.LoggingCallback("Filling gaps\n");
	for (int i = 0; i < Sections.Size(); i++) {
		ReLibData.LoggingCallback("Filling section %.8s (%llu lines)\n", SectionHeaders[i].Name, Sections[i].Lines->Size());

		// Incase section holds no lines
		if (!Sections[i].Lines->Size()) {	
			line.Type = Embed;
			line.OldRVA = Sections[i].OldRVA;
			if (Sections[i].OldSize < SectionHeaders[i].SizeOfRawData) {
				line.Embed.Size = Sections[i].OldSize;
				Sections[i].Lines->Push(line);
				continue;
			}
			line.Embed.Size = SectionHeaders[i].SizeOfRawData;
			if (line.OldRVA && line.Embed.Size) Sections[i].Lines->Push(line);
			line.Type = Padding;
			line.OldRVA += line.Embed.Size;
			line.Padding.Size = Sections[i].OldSize - (line.OldRVA - Sections[i].OldRVA);
			if (line.OldRVA && line.Padding.Size) Sections[i].Lines->Push(line);
			continue;
		}

		// Insert prepended data
		line.Type = Embed;
		if (Sections[i].Lines->At(0).OldRVA > Sections[i].OldRVA) {
			line.OldRVA = Sections[i].OldRVA;
			line.Embed.Size = Sections[i].Lines->At(0).OldRVA - Sections[i].OldRVA;
			Sections[i].Lines->Insert(0, line);
		} else if (Sections[i].Lines->At(0).OldRVA < Sections[i].OldRVA) {
			ReLibData.WarningCallback("First line in section %d begins below the section (you should *hopefully* never see this)\n", i);
		}

		// Insert embedded data
		for (int j = 0; j < Sections[i].Lines->Size() - 1; j++) {
			line.OldRVA = Sections[i].Lines->At(j).OldRVA + GetLineSize(Sections[i].Lines->At(j));
			if (line.OldRVA < Sections[i].Lines->At(j + 1).OldRVA) {
				line.Embed.Size = Sections[i].Lines->At(j + 1).OldRVA - line.OldRVA;
				Sections[i].Lines->Insert(j + 1, line);
				j++;
			}
		}

		// Insert ending data
		line.OldRVA = Sections[i].Lines->At(Sections[i].Lines->Size() - 1).OldRVA + GetLineSize(Sections[i].Lines->At(Sections[i].Lines->Size() - 1));
		if (line.OldRVA - Sections[i].OldRVA < SectionHeaders[i].SizeOfRawData && line.OldRVA - Sections[i].OldRVA < Sections[i].OldSize) {
			line.Embed.Size = ((Sections[i].OldSize < SectionHeaders[i].SizeOfRawData) ? Sections[i].OldSize : SectionHeaders[i].SizeOfRawData) - (line.OldRVA - Sections[i].OldRVA);
			Sections[i].Lines->Push(line);
		}

		// Insert padding
		line.Type = Padding;
		line.OldRVA = Sections[i].Lines->At(Sections[i].Lines->Size() - 1).OldRVA + GetLineSize(Sections[i].Lines->At(Sections[i].Lines->Size() - 1));
		line.Padding.Size = Sections[i].OldSize - (line.OldRVA - Sections[i].OldRVA);
		if (line.OldRVA && line.Padding.Size) Sections[i].Lines->Push(line);
	}
	ReLibData.LoggingCallback("Filled gaps\n");
	ReLibData.LoggingCallback("Finished disassembly\n");
	fProgress = 0.f;
	return true;
}

RELIB_EXPORT bool Asm::FromDis(_In_ Line* pLine, _In_opt_ Label* pLabel) {
	if (!pLine || pLine->Type != Decoded) return false;

	// Prefixes
	if (pLine->Decoded.Instruction.attributes & ZYDIS_ATTRIB_HAS_LOCK) pAsm->lock();
	if (pLine->Decoded.Instruction.attributes & ZYDIS_ATTRIB_HAS_REP) pAsm->rep();
	if (pLine->Decoded.Instruction.attributes & ZYDIS_ATTRIB_HAS_REPE) pAsm->repe();
	if (pLine->Decoded.Instruction.attributes & ZYDIS_ATTRIB_HAS_REPNE) pAsm->repne();
	if (pLine->Decoded.Instruction.attributes & ZYDIS_ATTRIB_HAS_REPZ) pAsm->repz();
	if (pLine->Decoded.Instruction.attributes & ZYDIS_ATTRIB_HAS_REPNZ) pAsm->repnz();
	if (pLine->Decoded.Instruction.attributes & ZYDIS_ATTRIB_HAS_XRELEASE) pAsm->xrelease();
	if (pLine->Decoded.Instruction.attributes & ZYDIS_ATTRIB_HAS_XACQUIRE) pAsm->xacquire();
	
	// Special instructions
	if (!pLine->Decoded.Instruction.operand_count_visible) {
		switch (pLine->Decoded.Instruction.mnemonic) {
		case ZYDIS_MNEMONIC_MOVSB: return pAsm->movsb();
		case ZYDIS_MNEMONIC_MOVSW: return pAsm->movsw();
		case ZYDIS_MNEMONIC_MOVSD: return pAsm->movsd();
		case ZYDIS_MNEMONIC_MOVSQ: return pAsm->movsq();
		case ZYDIS_MNEMONIC_STOSB: return pAsm->stosb();
		case ZYDIS_MNEMONIC_STOSW: return pAsm->stosw();
		case ZYDIS_MNEMONIC_STOSD: return pAsm->stosd();
		case ZYDIS_MNEMONIC_STOSQ: return pAsm->stosq();
		}
	}

	// Convert mnemonic
	InstId mnem = ZydisToAsmJit::Mnemonics[pLine->Decoded.Instruction.mnemonic];
	if (!mnem) {
		ReLibData.ErrorCallback("Failed to translate mnemonic: %d\n", pLine->Decoded.Instruction.mnemonic);
		return false;
	}

	// Convert operands
	Operand_ ops[4] = { 0 };
	for (int i = 0; i < pLine->Decoded.Instruction.operand_count_visible && i < 4; i++) {
		Mem memop;
		Imm immop;
		int scale = 0;
		
		switch (pLine->Decoded.Operands[i].type) {
		case ZYDIS_OPERAND_TYPE_IMMEDIATE:
			if (pLabel && pLine->Decoded.Instruction.operand_count_visible == 1) { // Probably jmp or smthn
				ops[0] = *pLabel;
			} else {
				immop = Imm();
				immop._setValueInternal(pLine->Decoded.Operands[i].imm.value.s, ImmType::kInt);
				ops[i] = immop;
			}
			break;
		case ZYDIS_OPERAND_TYPE_REGISTER:
			ops[i] = ZydisToAsmJit::Registers[pLine->Decoded.Operands[i].reg.value];
			break;
		case ZYDIS_OPERAND_TYPE_MEMORY:
			if (pLine->Decoded.Operands[i].mem.scale == 2) scale = 1;
			else if (pLine->Decoded.Operands[i].mem.scale == 4) scale = 2;
			else if (pLine->Decoded.Operands[i].mem.scale == 8) scale = 3;
			if (pLabel) {
				memop = Mem(*pLabel, ZydisToAsmJit::Registers[pLine->Decoded.Operands[i].mem.index], scale, 0);
			} else {
				memop = Mem(ZydisToAsmJit::Registers[pLine->Decoded.Operands[i].mem.base], ZydisToAsmJit::Registers[pLine->Decoded.Operands[i].mem.index], scale, pLine->Decoded.Operands[i].mem.disp.has_displacement ? (pLine->Decoded.Operands[i].mem.disp.value & 0xFFFFFFFF) : 0);
			}
			if (pLine->Decoded.Operands[i].mem.segment == ZYDIS_REGISTER_GS) memop.setSegment(gs);
			else if (pLine->Decoded.Operands[i].mem.segment == ZYDIS_REGISTER_FS) memop.setSegment(fs);
			memop.setSize(pLine->Decoded.Operands[i].size / 8);
			ops[i] = memop;
		}
	}
	if (pLine->Decoded.Instruction.operand_count_visible > 4) {
		ReLibData.WarningCallback("Unable to process all operands\n");
	}

	return !pAsm->_emit(mnem, ops[0], ops[1], ops[2], &ops[3]);
}

RELIB_EXPORT bool Asm::Assemble() {
	// Setup
	if (!Sections.Size()) return false;
	if (!pAsm) {
		ReLibData.ErrorCallback("Assembler not set\n");
		return false;
	}
	ReLibData.LoggingCallback("Assembling\n");
	Vector<Line>* pLines;
	Line line;

	// Count total number of lines
	ToDo = 0;
	Progress = 0;
	for (int i = 0; i < Sections.Size(); i++) {
		if (Sections[i].Lines) ToDo += Sections[i].Lines->Size();
	}

	// Linker data
	RemoveData(NTHeaders.OptionalHeader.DataDirectory[5].VirtualAddress, NTHeaders.OptionalHeader.DataDirectory[5].Size);
	Vector<DWORD> XREFs;
	Vector<Label> XREFLabels;
	Vector<Line> LinkLater;
	Vector<QWORD> LinkLaterOffsets;

	// Assemble sections
	for (DWORD SecIndex = 0; SecIndex < Sections.Size(); SecIndex++) {
		// Prepare next section
		AsmSection section = Sections[SecIndex];
		pLines = section.Lines;
		section.NewRVA = pAsm->offset() + SectionHeaders[0].VirtualAddress;
		DWORD rva = section.NewRVA;
		section.NewRawSize = 0;
		section.NewVirtualSize = 0;

		// Assemble lines
		for (int i = 0; i < pLines->Size(); i++) {
			fProgress = (float)i / (float)pLines->Size();
			line = pLines->At(i);
			line.NewRVA = rva;
			pLines->Replace(i, line);
			size_t off = pAsm->offset();

			switch (line.Type) {
			case Decoded: {
				// Calculate referenced address
				int rel = -1;
				uint64_t refs = 0;
				Label ah;
				if (IsInstructionCF(line.Decoded.Instruction.mnemonic) && line.Decoded.Operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
					rel = 0;
				} else {
					for (int i = 0; i < line.Decoded.Instruction.operand_count_visible; i++) {
						if (line.Decoded.Operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY && (line.Decoded.Operands[i].mem.base == ZYDIS_REGISTER_RIP || line.Decoded.Operands[i].mem.index == ZYDIS_REGISTER_RIP)) {
							rel = i;
							break;
						}
					}
				}
				if (rel >= 0) {
					refs = line.Decoded.refs;
					int loc = XREFs.Find(refs);
					if (loc < 0) {
						XREFs.Push(refs);
						ah = pAsm->newLabel();
						XREFLabels.Push(ah);
					} else {
						ah = XREFLabels[loc];
					}
				}

				// Encode
				FromDis(&line, rel >= 0 ? &ah : NULL);
				break;
			}
			case Embed: {
				Buffer buf = { 0 };
				buf.Allocate(line.Embed.Size);
				ReadRVA(line.OldRVA, buf.pBytes, line.Embed.Size);
				pAsm->embed(buf.pBytes, buf.u64Size);
				buf.Release();
				break;
			}
			case RawInsert:
				pAsm->embed(line.RawInsert.pBytes, line.RawInsert.u64Size);
				break;
			case Padding:
				section.NewVirtualSize += line.Padding.Size;
				pAsm->db(0, line.Padding.Size);
				if (i < pLines->Size() - 1) {
					ReLibData.ErrorCallback("Ran into padding in the middle of a section\n");
					return false;
				}
				break;
			case JumpTable:
				LinkLaterOffsets.Push(pAsm->offset());
				pAsm->dd(0);
				LinkLater.Push(line);
				break;
			case Pointer:
				LinkLaterOffsets.Push(pAsm->offset());
				if (line.Pointer.IsAbs) pAsm->dq(0);
				else pAsm->dd(0);
				LinkLater.Push(line);
			}

			rva += pAsm->offset() - off;
		}

		// Finalize section
		section.NewRawSize = pAsm->offset() - (section.NewRVA - SectionHeaders[0].VirtualAddress);
		section.NewRawSize -= section.NewVirtualSize;
		section.NewVirtualSize += section.NewRawSize;
		if (pAsm->offset() % NTHeaders.OptionalHeader.SectionAlignment) {
			pAsm->db(0, NTHeaders.OptionalHeader.SectionAlignment - pAsm->offset() % NTHeaders.OptionalHeader.SectionAlignment);
		}
		Sections[SecIndex] = section;
	}

	// Link
	fProgress = 0.f;
	ReLibData.LoggingCallback("Linking\n");
	if (XREFs.Size() != XREFLabels.Size()) {
		ReLibData.ErrorCallback("This should never happen (XREFs.Size() != XREFLabels.Size())\n");
		return false;
	}
	if (LinkLater.Size() != LinkLaterOffsets.Size()) {
		ReLibData.ErrorCallback("This should never happen part 2 (LinkLater.Size() != LinkLaterOffsets.Size())\n");
		return false;
	}
	for (int i = 0; i < LinkLater.Size(); i++) {
		line = LinkLater[i];
		if (line.Type == JumpTable) {
			line.JumpTable.Value = TranslateOldAddress((line.bRelative ? line.JumpTable.Base : 0) + line.JumpTable.Value);
			if (line.bRelative) {
				line.JumpTable.Base = TranslateOldAddress(line.JumpTable.Base);
				line.JumpTable.Value -= line.JumpTable.Base;
			}
			*reinterpret_cast<DWORD*>(pAsm->code()->textSection()->buffer().data() + LinkLaterOffsets[i]) = line.JumpTable.Value;
		} else if (line.Type == Pointer) {
			if (line.Pointer.IsAbs) {
				*reinterpret_cast<QWORD*>(pAsm->code()->textSection()->buffer().data() + LinkLaterOffsets[i]) = NTHeaders.OptionalHeader.ImageBase + TranslateOldAddress(line.Pointer.Abs - NTHeaders.OptionalHeader.ImageBase);
			} else {
				*reinterpret_cast<DWORD*>(pAsm->code()->textSection()->buffer().data() + LinkLaterOffsets[i]) = TranslateOldAddress(line.Pointer.RVA);
			}
		} else {
			ReLibData.ErrorCallback("This also should never happen (LinkLater[i].Type != JumpTable && LinkLater[i].Type != Pointer)\n");
			return false;
		}
	}
	for (int i = 0; i < XREFs.Size(); i++) {
		pAsm->code()->bindLabel(XREFLabels[i], pAsm->code()->textSection()->id(), TranslateOldAddress(XREFs[i]) - SectionHeaders[0].VirtualAddress);
	}
	LinkLater.Release();
	LinkLaterOffsets.Release();
	XREFs.Release();
	XREFLabels.Release();

	// Translate known addresses
	for (int i = 0; i < 16; i++) {
		if (i == 5) continue;
		NTHeaders.OptionalHeader.DataDirectory[i].VirtualAddress = TranslateOldAddress(NTHeaders.OptionalHeader.DataDirectory[i].VirtualAddress);
		if (NTHeaders.OptionalHeader.DataDirectory[i].VirtualAddress == _UI32_MAX) {
			ReLibData.WarningCallback("Failed to translate data directory %d\n", i);
			NTHeaders.OptionalHeader.DataDirectory[i].VirtualAddress = NTHeaders.OptionalHeader.DataDirectory[i].Size = 0;
		}
	}
	NTHeaders.OptionalHeader.AddressOfEntryPoint = TranslateOldAddress(NTHeaders.OptionalHeader.AddressOfEntryPoint);
	Vector<DWORD> Relocations = GetRelocations();
	for (int i = 0; i < Relocations.Size(); i++) {
		Relocations[i] = TranslateOldAddress(Relocations[i]);
		/*for (int j = 0; j < pAsm->code()->relocEntries().size(); j++) {
			if (pAsm->code()->relocEntries().at(j)->relocType() == RelocType::kAbsToAbs) {
				
			} else if (pAsm->code()->relocEntries().at(j)->relocType() != RelocType::kNone) {
				ReLibData.WarningCallback("Relocation not handled\n");
			}
		}*/
	}
	Buffer relocs = GenerateRelocSection(Relocations);
	NTHeaders.OptionalHeader.DataDirectory[5].Size = relocs.u64Size;

	// Copy data
	ReLibData.LoggingCallback("Finalizing\n");
	pAsm->code()->flatten();
	pAsm->code()->relocateToBase(NTHeaders.OptionalHeader.ImageBase + SectionHeaders[0].VirtualAddress);
	ReLibData.LoggingCallback("Assembled code has %d sections, and has %d relocations\n", pAsm->code()->sectionCount(), pAsm->code()->hasRelocEntries() ? pAsm->code()->relocEntries().size() : 0);
	if (pAsm->code()->hasUnresolvedLinks()) pAsm->code()->resolveUnresolvedLinks();
	if (pAsm->code()->hasUnresolvedLinks()) ReLibData.WarningCallback("Assembled code has %d unsolved links\n", pAsm->code()->unresolvedLinkCount());
	for (int i = 0; i < NTHeaders.FileHeader.NumberOfSections; i++) {
		SectionData[i].Release();
		Buffer buf = { 0 };
		SectionData[i] = buf;
		if (!Sections[i].NewVirtualSize && !Sections[i].NewRawSize) {
			DeleteSection(i);
			i--;
		}
		buf.Allocate(Sections[i].NewRawSize);
		if (pAsm->code()->textSection()->buffer().size() < Sections[i].NewRVA - SectionHeaders[0].VirtualAddress + buf.u64Size) {
			ReLibData.ErrorCallback("Failed to read assembled code (size: 0x%p, expected: 0x%p)\n", pAsm->code()->textSection()->buffer().size(), Sections[i].NewRVA - SectionHeaders[0].VirtualAddress + buf.u64Size);
			return false;
		}
		memcpy(buf.pBytes, pAsm->code()->textSection()->buffer().data() + Sections[i].NewRVA - SectionHeaders[0].VirtualAddress, buf.u64Size);
		SectionData[i] = buf;
		IMAGE_SECTION_HEADER header = SectionHeaders[i];
		header.VirtualAddress = Sections[i].NewRVA;
		header.SizeOfRawData = Sections[i].NewRawSize;
		header.Misc.VirtualSize = Sections[i].NewVirtualSize;
		header.Characteristics |= IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
		SectionHeaders[i] = header;
	}
	
	// Insert relocation data
	IMAGE_SECTION_HEADER RelocHeader = { 0 };
	RelocHeader.Misc.VirtualSize = RelocHeader.SizeOfRawData = relocs.u64Size;
	RelocHeader.VirtualAddress = SectionHeaders[SectionHeaders.Size() - 1].VirtualAddress + SectionHeaders[SectionHeaders.Size() - 1].Misc.VirtualSize;
	RelocHeader.VirtualAddress += (RelocHeader.VirtualAddress % NTHeaders.OptionalHeader.SectionAlignment) ? NTHeaders.OptionalHeader.SectionAlignment - (RelocHeader.VirtualAddress % NTHeaders.OptionalHeader.SectionAlignment) : 0;
	NTHeaders.OptionalHeader.DataDirectory[5].VirtualAddress = RelocHeader.VirtualAddress;
	RelocHeader.Characteristics = IMAGE_SCN_MEM_READ;
	memcpy(RelocHeader.Name, ".reloc\0", 8);
	SectionHeaders.Push(RelocHeader);
	SectionData.Push(relocs);
	NTHeaders.FileHeader.NumberOfSections++;

	// Fix exception data
	IMAGE_DATA_DIRECTORY ExcDataDir = NTHeaders.OptionalHeader.DataDirectory[3];
	if (ExcDataDir.VirtualAddress) {
		Buffer ExcData = SectionData[FindSectionByRVA(ExcDataDir.VirtualAddress)];
		IMAGE_SECTION_HEADER ExcSecHeader = SectionHeaders[FindSectionByRVA(ExcDataDir.VirtualAddress)];
		if (ExcData.pBytes && ExcSecHeader.VirtualAddress) {
			RUNTIME_FUNCTION* pArray = reinterpret_cast<RUNTIME_FUNCTION*>(ExcData.pBytes + ExcDataDir.VirtualAddress - ExcSecHeader.VirtualAddress);
			for (DWORD i = 0, n = ExcDataDir.Size / sizeof(RUNTIME_FUNCTION); i < n; i++) {
				CheckRuntimeFunction(&pArray[i], true);
			}
		}
	}

	// Fix function ranges
	for (int i = 0; i < FunctionRanges.Size(); i++) {
		FunctionRange range = FunctionRanges[i];
		for (int j = 0; j < range.Entries.Size(); j++) range.Entries[j] = TranslateOldAddress(range.Entries[j]);
		
		// Bandaid fix
		DWORD offset = 0;
		DWORD sec = FindSectionIndex(range.dwStart + range.dwSize);
		DWORD j = FindIndex(sec, range.dwStart + range.dwSize);
		offset = GetLineSize(Sections[sec].Lines->At(j));

		DWORD dwOldStart = range.dwStart;
		range.dwStart = TranslateOldAddress(dwOldStart);
		range.dwSize = TranslateOldAddress(dwOldStart + range.dwSize) - range.dwStart - offset;
		FunctionRanges[i] = range;
	}

	// Fix resources
	if (NTHeaders.OptionalHeader.DataDirectory[2].Size && NTHeaders.OptionalHeader.DataDirectory[2].VirtualAddress) {
		Vector<DWORD> Offsets;
		Offsets.Push(0);
		Vector<DWORD> Done;
		Done.Push(0);
		Vector<DWORD> Done2;
		IMAGE_RESOURCE_DIRECTORY Dir;
		IMAGE_RESOURCE_DIRECTORY_ENTRY Entry;
		DWORD dwOff = 0;
		do {
			dwOff = Offsets.Pop();
			Dir = ReadRVA<IMAGE_RESOURCE_DIRECTORY>(NTHeaders.OptionalHeader.DataDirectory[2].VirtualAddress + dwOff);
			for (int i = 0; i < Dir.NumberOfNamedEntries + Dir.NumberOfIdEntries; i++) {
				Entry = ReadRVA<IMAGE_RESOURCE_DIRECTORY_ENTRY>(NTHeaders.OptionalHeader.DataDirectory[2].VirtualAddress + dwOff + sizeof(IMAGE_RESOURCE_DIRECTORY) + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) * i);
				if (Entry.DataIsDirectory) {
					if (!Done.Includes(Entry.OffsetToDirectory)) {
						Offsets.Push(Entry.OffsetToDirectory);
						Done.Push(Entry.OffsetToDirectory);
					}
				} else if (!Done2.Includes(Entry.OffsetToData)) {
					Done2.Push(Entry.OffsetToData);
					IMAGE_RESOURCE_DATA_ENTRY Resource = ReadRVA<IMAGE_RESOURCE_DATA_ENTRY>(NTHeaders.OptionalHeader.DataDirectory[2].VirtualAddress + Entry.OffsetToData);
					Resource.OffsetToData = TranslateOldAddress(Resource.OffsetToData);
					WriteRVA<IMAGE_RESOURCE_DATA_ENTRY>(NTHeaders.OptionalHeader.DataDirectory[2].VirtualAddress + Entry.OffsetToData, Resource);
				}
			}
		} while (Offsets.Size());
		Done.Release();
		Done2.Release();
	}

	FixHeaders();
	ReLibData.LoggingCallback("Finished assembly\n");
	fProgress = 0.f;
	return true;
}

RELIB_EXPORT void Asm::CleanHeaders() {
	ZeroMemory(&DosHeader, sizeof(DosHeader));
	NTHeaders.FileHeader.TimeDateStamp = 0;
	NTHeaders.OptionalHeader.SizeOfCode = 0;
	NTHeaders.OptionalHeader.SizeOfInitializedData = 0;
	NTHeaders.OptionalHeader.SizeOfUninitializedData = 0;
	NTHeaders.OptionalHeader.BaseOfCode = 0;
	NTHeaders.OptionalHeader.MajorImageVersion = 0;
	NTHeaders.OptionalHeader.MinorImageVersion = 0;
	NTHeaders.OptionalHeader.Win32VersionValue = 0;
	NTHeaders.OptionalHeader.CheckSum = 0;
	NTHeaders.OptionalHeader.DataDirectory[12].VirtualAddress = 0;
	NTHeaders.OptionalHeader.DataDirectory[12].Size = 0;
	IMAGE_SECTION_HEADER sec = { 0 };
	for (int i = 0; i < SectionHeaders.Size(); i++) {
		sec = SectionHeaders[i];
		sec.Characteristics &= ~(IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_INITIALIZED_DATA);
		SectionHeaders[i] = sec;
	}
}

RELIB_EXPORT bool Asm::Strip() {
	ReLibData.LoggingCallback("Stripping PE\n");
	// Debug directory
	if (NTHeaders.OptionalHeader.DataDirectory[6].Size && NTHeaders.OptionalHeader.DataDirectory[6].VirtualAddress) {
		DWORD dwSize = NTHeaders.OptionalHeader.DataDirectory[6].Size;
		for (int i = 0, n = dwSize / sizeof(IMAGE_DEBUG_DIRECTORY); i < n; i++) {
			IMAGE_DEBUG_DIRECTORY debug = ReadRVA<IMAGE_DEBUG_DIRECTORY>(NTHeaders.OptionalHeader.DataDirectory[6].VirtualAddress + sizeof(IMAGE_DEBUG_DIRECTORY) * i);
			RemoveData(debug.AddressOfRawData, debug.SizeOfData);
			dwSize += debug.SizeOfData;
		}
		RemoveData(NTHeaders.OptionalHeader.DataDirectory[6].VirtualAddress, NTHeaders.OptionalHeader.DataDirectory[6].Size);
		ReLibData.LoggingCallback("Removed debug directory (%#x bytes)\n", dwSize);
		NTHeaders.OptionalHeader.DataDirectory[6].VirtualAddress = NTHeaders.OptionalHeader.DataDirectory[6].Size = 0;
	}

	// Symbol table
	if (NTHeaders.FileHeader.PointerToSymbolTable && NTHeaders.FileHeader.PointerToSymbolTable < OverlayOffset) {
		ReLibData.WarningCallback("Stripping non-overlay symbols, this is untested code!\n");
		// Find debug sections
		IMAGE_SYMBOL sym;
		DWORD rva = RawToRVA(NTHeaders.FileHeader.PointerToSymbolTable);
		DWORD end = rva + sizeof(IMAGE_SYMBOL) * NTHeaders.FileHeader.NumberOfSymbols;
		for (int i = 0; i < NTHeaders.FileHeader.NumberOfSymbols; i++) {
			ReadRVA(rva + sizeof(IMAGE_SYMBOL) * i, &sym, sizeof(IMAGE_SYMBOL));
			if (!sym.N.Name.Short) {
				char* str = ReadRVAString(rva + sizeof(IMAGE_SYMBOL) * NTHeaders.FileHeader.NumberOfSymbols + sym.N.Name.Long);
				int len = lstrlenA(str);
				end += len;
				if (len > 7) {
					char bak = str[7];
					str[7] = 0;
					if (!lstrcmpA(str, ".debug_")) {
						if (SectionHeaders[sym.SectionNumber - 1].Misc.VirtualSize || SectionHeaders[sym.SectionNumber - 1].VirtualAddress) {
							str[7] = bak;
							IMAGE_SECTION_HEADER Header = SectionHeaders[sym.SectionNumber - 1];
							Header.Misc.VirtualSize = 0;
							Header.VirtualAddress = 0;
							SectionHeaders[sym.SectionNumber - 1] = Header;
							ReLibData.LoggingCallback("Unloaded section %.8s (%s)\n", SectionHeaders[sym.SectionNumber - 1].Name, str);
						}
					}
					str[7] = bak;
				}
			}
		}
		RemoveData(rva, end - rva);
		ReLibData.LoggingCallback("Removed %d symbols\n", NTHeaders.FileHeader.NumberOfSymbols);
	}

	// Overlay
	if (NTHeaders.FileHeader.PointerToSymbolTable >= OverlayOffset) {
		IMAGE_SYMBOL* pSyms = reinterpret_cast<IMAGE_SYMBOL*>(Overlay.pBytes + (NTHeaders.FileHeader.PointerToSymbolTable - OverlayOffset));
		char* pStrs = reinterpret_cast<char*>(pSyms) + sizeof(IMAGE_SYMBOL) * NTHeaders.FileHeader.NumberOfSymbols;
		for (int i = 0; i < NTHeaders.FileHeader.NumberOfSymbols; i++) {
			if (!pSyms[i].N.Name.Short && pSyms[i].N.Name.Long) {
				char* str = pStrs + pSyms[i].N.Name.Long;
				if (lstrlenA(str) > 7) {
					char bak = str[7];
					str[7] = 0;
					if (!lstrcmpA(str, ".debug_")) {
						if (SectionHeaders[pSyms[i].SectionNumber - 1].Misc.VirtualSize || SectionHeaders[pSyms[i].SectionNumber - 1].VirtualAddress) {
							str[7] = bak;
							IMAGE_SECTION_HEADER Header = SectionHeaders[pSyms[i].SectionNumber - 1];
							Header.Misc.VirtualSize = 0;
							Header.VirtualAddress = 0;
							SectionHeaders[pSyms[i].SectionNumber - 1] = Header;
							ReLibData.LoggingCallback("Unloaded section %.8s (%s)\n", SectionHeaders[pSyms[i].SectionNumber - 1].Name, str);
						}
					}
					str[7] = bak;
				}
			}
		}
		ReLibData.LoggingCallback("Removed %d symbols\n", NTHeaders.FileHeader.NumberOfSymbols);
	}
	DiscardOverlay();

	// Useless sections
	for (WORD i = 0; i < NTHeaders.FileHeader.NumberOfSections; i++) {
		if (!SectionHeaders[i].VirtualAddress || !SectionHeaders[i].Misc.VirtualSize) {
			ReLibData.LoggingCallback("Removed section %.8s\n", SectionHeaders[i].Name);
			DeleteSection(i);
			i--;
		}
	}
	NTHeaders.FileHeader.PointerToSymbolTable = 0;
	NTHeaders.FileHeader.NumberOfSymbols = 0;
	NTHeaders.FileHeader.Characteristics |= IMAGE_FILE_LOCAL_SYMS_STRIPPED | IMAGE_FILE_DEBUG_STRIPPED;

	ReLibData.LoggingCallback("Stripped\n");
	return true;
}

RELIB_EXPORT void Asm::DeleteSection(_In_ WORD wIndex) {
	Sections.Remove(wIndex);
	PE::DeleteSection(wIndex);
}

RELIB_EXPORT DWORD Asm::GetAssembledSize(_In_ DWORD SectionIndex) {
	DWORD dwSize = 0;
	Vector<Line>* Lines = Sections[SectionIndex].Lines;
	for (DWORD i = 0; i < Lines->Size(); i++) {
		dwSize += GetLineSize(Lines->At(i));
	}
	return dwSize;
}

RELIB_EXPORT void Asm::InsertLine(_In_ DWORD SectionIndex, _In_ DWORD LineIndex, _In_ Line line) {
	if (SectionIndex >= Sections.Size() || LineIndex > Sections[SectionIndex].Lines->Size()) return;
	Sections[SectionIndex].Lines->Insert(LineIndex, line);
}

RELIB_EXPORT DWORD Asm::TranslateOldAddress(_In_ DWORD dwRVA) {
	if (dwRVA < NTHeaders.OptionalHeader.SizeOfHeaders) return dwRVA;

	// Check if in between headers
	DWORD SecIndex = 0;
	for (; SecIndex < Sections.Size(); SecIndex++) {
		if (dwRVA < Sections[SecIndex].OldRVA) {
			return (SecIndex ? (dwRVA + Sections[SecIndex - 1].NewRVA) - Sections[SecIndex - 1].OldRVA : dwRVA);
		}
		else if (dwRVA >= Sections[SecIndex].OldRVA && dwRVA < Sections[SecIndex].OldRVA + Sections[SecIndex].OldSize) {
			break;
		}
	}

	DWORD szIndex = FindIndex(SecIndex, dwRVA);
	if (szIndex == _UI32_MAX) {
		ReLibData.ErrorCallback("Failed to translate address 0x%p\n", NTHeaders.OptionalHeader.ImageBase + dwRVA);
		return 0;
	}
	if (szIndex < Sections[SecIndex].Lines->Size()) {
		return dwRVA + Sections[SecIndex].Lines->At(szIndex).NewRVA - Sections[SecIndex].Lines->At(szIndex).OldRVA;
	}
	
	return dwRVA + Sections[SecIndex].NewRVA - Sections[SecIndex].OldRVA;
}

RELIB_EXPORT void Asm::DeleteLine(_In_ DWORD SectionIndex, _In_ DWORD LineIndex) {
	Sections[SectionIndex].Lines->Remove(LineIndex);
}

RELIB_EXPORT void Asm::RemoveData(_In_ DWORD dwRVA, _In_ DWORD dwSize) {
	DWORD sec = FindSectionIndex(dwRVA);
	DWORD i = FindIndex(sec, dwRVA);
	if (i == _UI32_MAX) {
		ReLibData.WarningCallback("Failed to remove data at range 0x%p - 0x%p\n", NTHeaders.OptionalHeader.ImageBase + dwRVA, NTHeaders.OptionalHeader.ImageBase + dwRVA + dwSize);
		return;
	}

	Line data = Sections[sec].Lines->At(i);
	if (data.Type != Embed || data.OldRVA > dwRVA || data.OldRVA + GetLineSize(data) < dwRVA + dwSize) {
		ReLibData.WarningCallback("Failed to remove data at range 0x%p - 0x%p (this version can be fixed later)\n", NTHeaders.OptionalHeader.ImageBase + dwRVA, NTHeaders.OptionalHeader.ImageBase + dwRVA + dwSize);
		return;
	}

	Line data_new;
	data_new.Type = Embed;
	if (data.OldRVA < dwRVA) {
		data_new.OldRVA = data.OldRVA;
		data_new.Embed.Size = dwRVA - data_new.OldRVA;
		InsertLine(sec, i, data_new);
		i++;
	}
	if (data.OldRVA + GetLineSize(data) > dwRVA + dwSize) {
		data_new.OldRVA = dwRVA + dwSize;
		data_new.Embed.Size = data.OldRVA + GetLineSize(data) - (dwRVA + dwSize);
		InsertLine(sec, i, data_new);
		i++;
	}
	DeleteLine(sec, i);
}

RELIB_EXPORT Vector<FunctionRange> Asm::GetDisassembledFunctionRanges() {
	Vector<FunctionRange> clone = FunctionRanges;
	//clone.bCannotBeReleased = true;
	return clone;
}

RELIB_EXPORT DWORD GetLineSize(_In_ const Line& line) {
	switch (line.Type) {
	case Decoded:
		return line.Decoded.Instruction.length;
	case Embed:
		return line.Embed.Size;
	case Padding:
		return line.Padding.Size;
	case JumpTable:
		return sizeof(DWORD);
	case RawInsert:
		return line.RawInsert.u64Size;
	case Pointer:
		return (line.Pointer.IsAbs ? sizeof(uint64_t) : sizeof(DWORD));
	}
	ReLibData.ErrorCallback("Failed to calculate length of instruction (unknown type)\n");
	return 0;
}

RELIB_EXPORT Vector<AsmSection> Asm::GetSections() {
	Vector<AsmSection> clone = Sections;
	//clone.bCannotBeReleased = true;
	return clone;
}