/*!
 * @file asm.cpp
 * @author undisassemble
 * @brief Assembly related functions
 * @version 0.0.0
 * @date 2025-12-18
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

RELIB_EXPORT void Line::ToString(_Out_ char* pOutStr, _In_ DWORD nOutStr, _In_ ZydisFormatter Formatter) const {
	if (!pOutStr || !nOutStr) return;
	ZeroMemory(pOutStr, nOutStr);
	ZydisDecodedInstruction DecodedInst;
	ZydisDecodedOperand DecodedOps[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];
	switch (Type) {
	case LineType::Decoded:
		DecodedInst = Decoded.Instruction;
		for (int i = 0; i < Decoded.Instruction.operand_count_visible; i++) DecodedOps[i] = Decoded.Operands[i];
		ZydisFormatterFormatInstruction(&Formatter, &DecodedInst, DecodedOps, DecodedInst.operand_count_visible, pOutStr, nOutStr, OldRVA, NULL);
		break;
	case LineType::Embed:
		snprintf(pOutStr, nOutStr, "data (%lx)", Embed.Size);
		break;
	case LineType::JumpTable:
		snprintf(pOutStr, nOutStr, "dd p_%08lx", (bRelative ? JumpTable.Base : 0) + JumpTable.Value);
		break;
	case LineType::Padding:
		snprintf(pOutStr, nOutStr, "pad (%lx)", Padding.Size);
		break;
	case LineType::Pointer:
		if (Pointer.IsAbs) {
			snprintf(pOutStr, nOutStr, "dq p_%08llx", Pointer.Abs);
		} else {
			snprintf(pOutStr, nOutStr, "dd p_%08lx", Pointer.RVA);
		}
		break;
	case LineType::RawInsert:
		snprintf(pOutStr, nOutStr, "insert (%llx)", RawInsert.Size());
	}
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
		_ReLibData.WarningCallback("I don\'t know if this works, operand.ptr.segment = %d\n", operand.ptr.segment);
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
		ret.imm.is_relative = false;
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
	AsmSection sec = { 0 };
	for (int i = 0; i < SectionHeaders.Size(); i++) {
		sec.Lines = new Vector<Line>;
		sec.Lines->bExponentialGrowth = true;
		sec.OldRVA = SectionHeaders[i].VirtualAddress;
		sec.OldSize = SectionHeaders[i].Misc.VirtualSize;
		Sections.Push(sec);
	}
}

RELIB_EXPORT Asm::Asm(_In_ HANDLE hFile) : PE(hFile) {
	ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
	AsmSection sec = { 0 };
	for (int i = 0; i < SectionHeaders.Size(); i++) {
		sec.Lines = new Vector<Line>;
		sec.Lines->bExponentialGrowth = true;
		sec.NewRVA = sec.OldRVA = SectionHeaders[i].VirtualAddress;
		sec.OldSize = SectionHeaders[i].Misc.VirtualSize;
		Sections.Push(sec);
	}
}

RELIB_EXPORT Asm::~Asm() {
	for (int i = 0; i < Sections.Size(); i++) if (Sections[i].Lines) {
		Sections[i].Lines->Release();
		delete Sections[i].Lines;
	}
	Sections.Release();
	JumpTables.Release();
	JumpTableIndexers.Release();
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
	if (dwSec >= Sections.Size()) return _UI32_MAX;
	Vector<Line>* Lines = Sections[dwSec].Lines;
	RELIB_ASSERT(Lines != NULL);

	// If no lines exist, it will just be the first line
	if (!Lines->Size())
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
		if (i == PrevI || i == _UI32_MAX) break;

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
	if (dwSec >= Sections.Size()) return _UI32_MAX;
	Vector<Line>* Lines = Sections[dwSec].Lines;
	RELIB_ASSERT(Lines != NULL);

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
			// After end
			DWORD next = GetNextOriginal(dwSec, i + 1);
			if (i == Lines->Size() - 1 || next == _UI32_MAX) {
				return Lines->Size();
			}
			
			// In between
			if (dwRVA < Lines->At(next).OldRVA) {
				return next;
			}

			// Shift range
			szMin = i;
		}

		else if (dwRVA < Lines->At(i).OldRVA) {
			// Before first || in between prev
			DWORD prev = GetPrevOriginal(dwSec, i - 1);
			if (prev == _UI32_MAX || !i || dwRVA > Lines->At(prev).OldRVA + GetLineSize(Lines->At(prev))) {
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

RELIB_EXPORT void Asm::FindFunctions() {
	for (long long FunctionIndex = 0; FunctionIndex < Functions.Size(); FunctionIndex++) {
		// Setup
		if (!Functions[FunctionIndex]) continue;
		FunctionRange CurrentFunction;

		// Get entry
		DWORD SecIndex = FindSectionIndex(Functions[FunctionIndex]);
		if (SecIndex == _UI32_MAX) {
			_ReLibData.WarningCallback("Failed to find function entry %08x\n", Functions[FunctionIndex]);
			continue;
		}
		Vector<Line>* pLines = Sections[SecIndex].Lines;
		DWORD LineIndex = FindIndex(SecIndex, Functions[FunctionIndex]);
		if (LineIndex == _UI32_MAX || !pLines) {
			_ReLibData.WarningCallback("Failed to find function entry %08x\n", Functions[FunctionIndex]);
			continue;
		}
		if (pLines->At(LineIndex).Type != Decoded) {
			_ReLibData.WarningCallback("Skipping function at %08x\n", Functions[FunctionIndex]);
			continue;
		}

		// If the function just jmps, add it as a possibility and skip it
		if (pLines->At(LineIndex).Decoded.Instruction.mnemonic == ZYDIS_MNEMONIC_JMP) {
			ZydisDecodedInstruction zdi = pLines->At(LineIndex).Decoded.Instruction;
			ZydisDecodedOperand op = pLines->At(LineIndex).Decoded.Operands[0];
			uint64_t out = 0;
			if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&zdi, &op, pLines->At(LineIndex).OldRVA, &out)) && !Functions.Includes(out)) Functions.Push(out);
			continue;
		}

		CurrentFunction.dwEntry = Functions[FunctionIndex];
		CurrentFunction.dwStart = Functions[FunctionIndex];
		Vector<DWORD> ToDo;
		Vector<DWORD> Done;
		DWORD current;
		ToDo.Push(Functions[FunctionIndex]);

		while (ToDo.Size()) {
			if (!LineIndex) {
				current = ToDo.Pop();
				Done.Push(current);
				LineIndex = FindIndex(SecIndex, current);
				if (LineIndex == _UI32_MAX) {
					_ReLibData.WarningCallback("Couldn't follow function segment at %08x\n", current);
					LineIndex = 0;
					continue;
				}
			}

			if (pLines->At(LineIndex).Type != Decoded) {
				_ReLibData.WarningCallback("Control flow of function %08x reached non-code segment, trashing\n", pLines->At(LineIndex).OldRVA);
				CurrentFunction.dwEntry = 0;
				ToDo.Release();
				break;
			}

			// Check if current instruction enters other function (for noreturn)
			if (Functions[FunctionIndex] != pLines->At(LineIndex).OldRVA && Functions.Includes(pLines->At(LineIndex).OldRVA)) {
				LineIndex = 0;
				continue;
			}
			
			// Add current instruction
			if (pLines->At(LineIndex).OldRVA < CurrentFunction.dwStart) {
				CurrentFunction.dwStart = pLines->At(LineIndex).OldRVA;
			}
			if (pLines->At(LineIndex).OldRVA + GetLineSize(pLines->At(LineIndex)) > CurrentFunction.dwStart + CurrentFunction.dwSize) {
				CurrentFunction.dwSize = pLines->At(LineIndex).OldRVA + GetLineSize(pLines->At(LineIndex)) - CurrentFunction.dwStart;
			}

			// CF
			if (IsInstructionCF(pLines->At(LineIndex).Decoded.Instruction.mnemonic) && pLines->At(LineIndex).Decoded.Operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && pLines->At(LineIndex).Decoded.Instruction.mnemonic != ZYDIS_MNEMONIC_CALL) {
				ZydisDecodedInstruction zdi = pLines->At(LineIndex).Decoded.Instruction;
				ZydisDecodedOperand op = pLines->At(LineIndex).Decoded.Operands[0];
				uint64_t out = 0;
				ZyanStatus stat;
				if (ZYAN_SUCCESS(stat = ZydisCalcAbsoluteAddress(&zdi, &op, pLines->At(LineIndex).OldRVA, &out))) {
					if (!Done.Includes(out) && !Functions.Includes(out)) ToDo.Push(out);
				} else {
					_ReLibData.WarningCallback("Couldn't follow function segment at %08x (%s)\n", pLines->At(LineIndex).OldRVA, ZydisErrorToString(stat));
					LineIndex = 0;
					continue;
				}
				if (pLines->At(LineIndex).Decoded.Instruction.mnemonic == ZYDIS_MNEMONIC_JMP) {
					LineIndex = 0;
					continue;
				}
			}

			// Check for return
			if (pLines->At(LineIndex).Decoded.Instruction.mnemonic == ZYDIS_MNEMONIC_RET) {
				LineIndex = 0;
				continue;
			}

			if (LineIndex) LineIndex++;
 		}
		ToDo.Release();
		Done.Release();

		if (CurrentFunction.dwEntry) FunctionRanges.Push(CurrentFunction);
	}
	Functions.Release();
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
	size_t szBufferOffset = 0;
	bool bFailGracefully = false;

	do {
		// Setup
		dwRVA = ToDisasm.Pop();
		TempLines.Release();
		if (!dwRVA) {
			_ReLibData.WarningCallback("Skipping NULL RVA\n");
			continue;
		} else if (dwRVA < Sections[0].OldRVA || dwRVA >= Sections[Sections.Size() - 1].OldRVA + Sections[Sections.Size() - 1].OldSize) {
			_ReLibData.WarningCallback("Skipping invalid RVA (%08x)\n", dwRVA);
			continue;
		}
		SectionIndex = FindSectionIndex(dwRVA);
		if (SectionIndex > Sections.Size()) {
			_ReLibData.ErrorCallback("Failed to find index of section at 0x%p\n", NTHeaders.OptionalHeader.ImageBase + dwRVA);
			return false;
		}
		Lines = Sections[SectionIndex].Lines;
		RELIB_ASSERT(Lines != NULL);
		Buffer RawBytes;
		{
			RawBytes = SectionData[FindSectionByRVA(dwRVA)];
			IMAGE_SECTION_HEADER Header = SectionHeaders[FindSectionByRVA(dwRVA)];
			if (!RawBytes.Data() || !RawBytes.Size() || !Header.Misc.VirtualSize) {
				_ReLibData.WarningCallback("Failed to get bytes at 0x%p\n", NTHeaders.OptionalHeader.ImageBase + dwRVA);
				continue;
			}
			szBufferOffset = dwRVA - Header.VirtualAddress;
			if (szBufferOffset >= RawBytes.Size()) {
				_ReLibData.WarningCallback("Attempted to disassemble uninitialized memory\n");
				continue;
			}
		}

		// Locate current position in index
		DWORD i = FindPosition(SectionIndex, dwRVA);
		if (i > Lines->Size()) {
			if (i == _UI32_MAX - 1) continue; // Already disassembled
			_ReLibData.ErrorCallback("Failed to find position for instruction at 0x%p\n", NTHeaders.OptionalHeader.ImageBase + dwRVA);
			return false;
		}

		// Start disassembling
		Line CraftedLine;
		CraftedLine.Type = Decoded;
		ZyanStatus Status;
		while (RawBytes.Size() && ZYAN_SUCCESS(Status = ZydisDecoderDecodeFull(&Decoder, RawBytes.Data() + szBufferOffset, RawBytes.Size() - szBufferOffset, &Instruction, Operands))) {
			// Convert
			CraftedLine.Decoded.Instruction = Instruction;
			for (int i = 0; i < CraftedLine.Decoded.Instruction.operand_count; i++) {
				CraftedLine.Decoded.Operands[i] = Operands[i];
			}
			CraftedLine.OldRVA = dwRVA;
			if (IsInstructionCF(Instruction.mnemonic)) {
				ZydisCalcAbsoluteAddress(&Instruction, Operands, CraftedLine.OldRVA, &CraftedLine.Decoded.refs);
			} else {
				for (int i = 0; i < Instruction.operand_count_visible; i++) {
					if (Operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY && Operands[i].mem.base == ZYDIS_REGISTER_RIP) {
						if (ZYAN_FAILED(ZydisCalcAbsoluteAddress(&Instruction, &Operands[i], CraftedLine.OldRVA, &CraftedLine.Decoded.refs))) {
							_ReLibData.WarningCallback("Could not calculate referenced address (0x%p)\n", NTHeaders.OptionalHeader.ImageBase + dwRVA);
						}
						break;
					}
				}
			}

			// Edit progress
			Progress += Instruction.length;
			fProgress = (float)Progress / (float)ToDo;

			TempLines.Push(CraftedLine);
			
			if (CraftedLine.Decoded.Instruction.mnemonic == ZYDIS_MNEMONIC_RET || CraftedLine.Decoded.Instruction.mnemonic == ZYDIS_MNEMONIC_INT3) break;
 
			if (IsInstructionCF(CraftedLine.Decoded.Instruction.mnemonic)) {
				// Jump table detection
				if (CraftedLine.Decoded.Instruction.mnemonic == ZYDIS_MNEMONIC_JMP && CraftedLine.Decoded.Operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
					// Walk backwards on current block
					ZydisRegister TableBase = ZYDIS_REGISTER_NONE;
					uint64_t JumpTableAddress = 0;
					uint64_t PotentialBase = 0;
					uint64_t NumItems = 0;
					bool bRelativeToBase = false;
					bool bWorking = true;
					for (int i = TempLines.Size() - 1; i >= 0; i--) {
						if (((bRelativeToBase && PotentialBase) || JumpTableAddress) && NumItems) break;

						if (TempLines[i].Type != Decoded) {
							_ReLibData.WarningCallback("Switch at %p failed (type 0)\n", NTHeaders.OptionalHeader.ImageBase + CraftedLine.OldRVA);
							bWorking = false;
							break;
						}
						
						// Get register containing the base
						if (!JumpTableAddress && TempLines[i].Decoded.Instruction.mnemonic == ZYDIS_MNEMONIC_ADD && TempLines[i].Decoded.Operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && TempLines[i].Decoded.Operands[0].reg.value == CraftedLine.Decoded.Operands[0].reg.value) {
							if (TableBase != ZYDIS_REGISTER_NONE || TempLines[i].Decoded.Operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER) {
								_ReLibData.WarningCallback("Switch at %p failed (type 1)\n", NTHeaders.OptionalHeader.ImageBase + CraftedLine.OldRVA);
								bWorking = false;
								break;
							}
							TableBase = TempLines[i].Decoded.Operands[1].reg.value;
						}

						// Get the base
						if (!JumpTableAddress && TempLines[i].Decoded.Instruction.mnemonic == ZYDIS_MNEMONIC_LEA && TempLines[i].Decoded.Operands[0].reg.value == TableBase) {
							ZydisDecodedInstruction inst = TempLines[i].Decoded.Instruction;
							ZydisDecodedOperand op = TempLines[i].Decoded.Operands[1];
							if (ZYAN_FAILED(ZydisCalcAbsoluteAddress(&inst, &op, TempLines[i].OldRVA, &JumpTableAddress))) {
								_ReLibData.WarningCallback("Switch at %p failed (type 2)\n", NTHeaders.OptionalHeader.ImageBase + CraftedLine.OldRVA);
								bWorking = false;
								break;
							}
							_ReLibData.LoggingCallback("Predicted jump table at %p\n", NTHeaders.OptionalHeader.ImageBase + JumpTableAddress);
							if (!JumpTableAddress) {
								JumpTableAddress = -1;
								bRelativeToBase = true;
							}
						}

						// Get other stuff
						if ((TempLines[i].Decoded.Instruction.mnemonic == ZYDIS_MNEMONIC_MOV || TempLines[i].Decoded.Instruction.mnemonic == ZYDIS_MNEMONIC_MOVSXD) && TempLines[i].Decoded.Operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
							if (!JumpTableAddress && TempLines[i].Decoded.Operands[1].mem.disp.has_displacement && TempLines[i].Decoded.Operands[1].mem.base != ZYDIS_REGISTER_NONE && TempLines[i].Decoded.Operands[1].mem.index != ZYDIS_REGISTER_NONE && TempLines[i].Decoded.Operands[1].mem.scale == 4 && !PotentialBase) {
								PotentialBase = TempLines[i].Decoded.Operands[1].mem.disp.value;
								bRelativeToBase = true;
								JumpTableIndexers.Push(TempLines[i].OldRVA);
							}
						}

						// Get bounds
						if (!NumItems && TempLines[i].Decoded.Instruction.mnemonic == ZYDIS_MNEMONIC_JNBE && i > 0 && TempLines[i - 1].Type == Decoded && TempLines[i - 1].Decoded.Instruction.mnemonic == ZYDIS_MNEMONIC_CMP && TempLines[i - 1].Decoded.Operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
							NumItems = (TempLines[i - 1].Decoded.Operands[1].imm.is_signed ? TempLines[i - 1].Decoded.Operands[1].imm.value.s : TempLines[i - 1].Decoded.Operands[1].imm.value.u) + 1;
						}
					}

					if (bRelativeToBase) JumpTableAddress = PotentialBase;

					// Add jump table entries
					if (bWorking && JumpTableAddress) {
						if (!NumItems) {
							_ReLibData.WarningCallback("Jump table at %p has an unknown number of cases.\n", NTHeaders.OptionalHeader.ImageBase + JumpTableAddress);
							bWorking = false;
						}
						Line TempJumpTable;
						TempJumpTable.Type = JumpTable;
						TempJumpTable.bRelative = !bRelativeToBase;
						TempJumpTable.JumpTable.Base = JumpTableAddress;
						WORD dwSec = FindSectionByRVA(bRelativeToBase ? PotentialBase : JumpTableAddress);
						if (dwSec == _UI16_MAX) {
							_ReLibData.WarningCallback("Failed to insert jump table contents at %p\n", NTHeaders.OptionalHeader.ImageBase + JumpTableAddress);
						} else {
							DWORD i = 0;
							while (!bWorking || NumItems) {
								// Get jump table case
								TempJumpTable.OldRVA = JumpTableAddress;
								TempJumpTable.JumpTable.Value = ReadRVA<DWORD>(JumpTableAddress);
								WORD dwCaseSec = FindSectionByRVA(TempJumpTable.JumpTable.Value + (bRelativeToBase ? 0 : TempJumpTable.JumpTable.Base));
								if (dwCaseSec == _UI16_MAX || ~SectionHeaders[dwCaseSec].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
									if (bWorking) _ReLibData.WarningCallback("Jump table %p ran into invalid value at %p\n", NTHeaders.OptionalHeader.ImageBase + TempJumpTable.JumpTable.Base, NTHeaders.OptionalHeader.ImageBase + JumpTableAddress);
									break;
								}
								
								// Insert data
								i = FindPosition(dwSec, JumpTableAddress);
								if (i == _UI32_MAX) {
									_ReLibData.WarningCallback("Failed to insert jump case at %p\n", NTHeaders.OptionalHeader.ImageBase + JumpTableAddress);
								} else if (i == _UI32_MAX - 1) {
									DWORD t = FindIndex(dwSec, JumpTableAddress);
									
									if (bWorking || (Sections[dwSec].Lines->At(t).Type == JumpTable  && Sections[dwSec].Lines->At(t).JumpTable.Base < TempJumpTable.JumpTable.Base)) {
										_ReLibData.WarningCallback("Jump table overriding data at %p\n", NTHeaders.OptionalHeader.ImageBase + JumpTableAddress);
										
										// Remove it from the jump table index so the old version doesnt get disassembled
										if (Sections[dwSec].Lines->At(t).Type == JumpTable) {
											int j = JumpTables.Find(Sections[dwSec].Lines->At(t).JumpTable.Value + (bRelativeToBase ? Sections[dwSec].Lines->At(t).bRelative : Sections[dwSec].Lines->At(t).JumpTable.Base));
											if (j != -1) JumpTables.Remove(j);
										}
										
										// Overwrite it if a less accurate switch parser dealt with it
										Sections[dwSec].Lines->Remove(t);
										Sections[dwSec].Lines->Insert(FindPosition(dwSec, JumpTableAddress), TempJumpTable);
										if (!JumpTables.Includes(TempJumpTable.JumpTable.Value + (bRelativeToBase ? 0 : TempJumpTable.JumpTable.Base)))
											JumpTables.Push(TempJumpTable.JumpTable.Value + (bRelativeToBase ? 0 : TempJumpTable.JumpTable.Base));
									}
								} else if (i != _UI32_MAX - 1) {
									Sections[dwSec].Lines->Insert(i, TempJumpTable);
									if (!JumpTables.Includes(TempJumpTable.JumpTable.Value + (bRelativeToBase ? 0 : TempJumpTable.JumpTable.Base)))
										JumpTables.Push(TempJumpTable.JumpTable.Value + (bRelativeToBase ? 0 : TempJumpTable.JumpTable.Base));
								}
								
								JumpTableAddress += sizeof(DWORD);
								NumItems--;
							}
						}
					}
				}

				// Calculate absolute address
				if (!((CraftedLine.Decoded.Operands[0].type != ZYDIS_OPERAND_TYPE_MEMORY && CraftedLine.Decoded.Operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) || (CraftedLine.Decoded.Operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && (CraftedLine.Decoded.Operands[0].mem.base != ZYDIS_REGISTER_RIP && CraftedLine.Decoded.Operands[0].mem.base != ZYDIS_REGISTER_NONE)))) {
					uint64_t u64Referencing = 0;
					if (ZYAN_FAILED(ZydisCalcAbsoluteAddress(&Instruction, &Operands[0], CraftedLine.OldRVA, &u64Referencing))) {
						_ReLibData.ErrorCallback("Failed to disassemble instruction at 0x%p\n", NTHeaders.OptionalHeader.ImageBase + CraftedLine.OldRVA);
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
								_ReLibData.ErrorCallback("Failed to disassemble code pointed to at 0x%p\n", NTHeaders.OptionalHeader.ImageBase + u64Referencing);
								TempLines.Release();
								return false;
							}
							
							// Extract the address
							Line insert;
							insert.OldRVA = u64Referencing;
							u64Referencing = ReadRVA<uint64_t>(u64Referencing);
							if (!u64Referencing) {
								_ReLibData.WarningCallback("Failed to retrieve address at 0x%p\n", NTHeaders.OptionalHeader.ImageBase + insert.OldRVA);
								u64Referencing = 0;
							} else if (u64Referencing < NTHeaders.OptionalHeader.ImageBase) {
								_ReLibData.WarningCallback("Skipping ref at 0x%p, possibly imported?\n", NTHeaders.OptionalHeader.ImageBase + insert.OldRVA);
								u64Referencing = 0;
							} else {
								// Insert address
								insert.Type = Pointer;
								insert.Pointer.IsAbs = true;
								insert.Pointer.Abs = u64Referencing;
								{
									WORD wInsertAt = FindPosition(wContainingIndex, insert.OldRVA);
									if (wInsertAt == _UI16_MAX) {
										_ReLibData.WarningCallback("Failed to find position to insert line at 0x%p\n", NTHeaders.OptionalHeader.ImageBase + insert.OldRVA);
									} else if (wInsertAt != _UI16_MAX - 1) {
										Sections[wContainingIndex].Lines->Insert(wInsertAt, insert);
									}
								}

								u64Referencing -= NTHeaders.OptionalHeader.ImageBase;
							}
						}
					}

					if (u64Referencing) {
						// Disassemble the address (if good)
						WORD wIndex = FindSectionByRVA(u64Referencing);
						if (wIndex >= SectionHeaders.Size()) {
							_ReLibData.WarningCallback("Failed to find section containing address 0x%p\n", NTHeaders.OptionalHeader.ImageBase + u64Referencing);
						} else {
							IMAGE_SECTION_HEADER Header = SectionHeaders[wIndex];
							if (Header.Characteristics & IMAGE_SCN_MEM_EXECUTE && Header.SizeOfRawData > u64Referencing - Header.VirtualAddress) {
								if (!ToDisasm.Includes(u64Referencing)) {
									ToDisasm.Push(u64Referencing);
									if (CraftedLine.Decoded.Instruction.mnemonic == ZYDIS_MNEMONIC_CALL && !Functions.Includes(u64Referencing)) {
										Functions.Push(u64Referencing);
									}
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
			szBufferOffset += CraftedLine.Decoded.Instruction.length;

			// Stop disassembly if the next instruction has already been disassembled
			if (i < Lines->Size() && Lines->At(i).OldRVA == dwRVA) {
				break;
			}
		}
		if (ZYAN_FAILED(Status)) {
			_ReLibData.WarningCallback("Zydis failed to disassemble bytes at 0x%p with code %s\n", NTHeaders.OptionalHeader.ImageBase + dwRVA, ZydisErrorToString(Status));
			bFailGracefully = true;
		}

		// Insert lines
		if (!TempLines.Size()) {
			_ReLibData.WarningCallback("Attempted to disassemble but got nothing\n");
			continue;
		}
		i = FindPosition(SectionIndex, TempLines[0].OldRVA);
		if (i > Lines->Size() || i == _UI32_MAX || i == _UI32_MAX - 1) {
			_ReLibData.WarningCallback("Re-checked insertion position and it\'s now invalid\n");
			continue;
		}
		Lines->Insert(i, TempLines);
	} while (ToDisasm.Size());

	ToDisasm.Release();
	return !bFailGracefully;
}

RELIB_EXPORT bool Asm::CheckRuntimeFunction(_In_ DWORD FuncRVA) {
	// Add entry to function list
	RUNTIME_FUNCTION Func = ReadRVA<RUNTIME_FUNCTION>(FuncRVA);
	if (!Functions.Includes(Func.BeginAddress)) Functions.Push(Func.BeginAddress);
	
	// Insert pointers
	WORD iSection = FindSectionByRVA(FuncRVA);
	DWORD iInsert = FindPosition(iSection, FuncRVA);
	if (iSection != _UI16_MAX && iInsert != _UI32_MAX && iInsert != _UI32_MAX - 1) {
		Vector<Line> FuncPtrs;
		Line ptr;
		ptr.Type = Pointer;
		ptr.OldRVA = FuncRVA;
		ptr.Pointer.IsAbs = false;
		ptr.Pointer.RVA = Func.BeginAddress;
		FuncPtrs.Push(ptr);
		ptr.OldRVA += sizeof(DWORD);
		ptr.Pointer.RVA = Func.EndAddress;
		FuncPtrs.Push(ptr);
		ptr.OldRVA += sizeof(DWORD);
		ptr.Pointer.RVA = Func.UnwindData;
		FuncPtrs.Push(ptr);
		Sections[iSection].Lines->Insert(iInsert, FuncPtrs);
		FuncPtrs.Release();
	}

	// Disassemble
	if (Func.BeginAddress && !DisasmRecursive(Func.BeginAddress))
		return false;

	// Check unwind info for function
	UNWIND_INFO UnwindInfo = ReadRVA<UNWIND_INFO>(Func.UnwindData);
	if (UnwindInfo.NumUnwindCodes & 1) UnwindInfo.NumUnwindCodes++; // Alignment

	// Get address of next handler
	DWORD CurrentRVA = Func.UnwindData + sizeof(UNWIND_INFO) + UnwindInfo.NumUnwindCodes * sizeof(UNWIND_CODE);
	// DWORD EndingRVA = 0;
	// if (NextRVA) {
	// 	EndingRVA = ReadRVA<RUNTIME_FUNCTION>(NextRVA).UnwindData;
	// } else {
	// 	iSection = FindSectionByRVA(Func.UnwindData);
	// 	if (iSection == _UI16_MAX) {
	// 		_ReLibData.WarningCallback("Failed to get section with unwind at 0x%08lx\n", Func.UnwindData);
	// 	} else {
	// 		EndingRVA = GetSections()[iSection].OldRVA + GetSections()[iSection].OldSize;
	// 	}
	// }

	// Check for handler
	if (/* (!EndingRVA || CurrentRVA + sizeof(DWORD) <= EndingRVA) && */ (UnwindInfo.Flags & UNW_FLAG_EHANDLER || UnwindInfo.Flags & UNW_FLAG_UHANDLER)) {
		// Get handler RVA
		DWORD HandlerRVA = ReadRVA<DWORD>(CurrentRVA);
		iSection = FindSectionByRVA(HandlerRVA);
		if (iSection == _UI16_MAX || !HandlerRVA || !(SectionHeaders[iSection].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
			_ReLibData.WarningCallback("Invalid handler RVA at 0x%08llx\n", NTHeaders.OptionalHeader.ImageBase + CurrentRVA);
			return true;
		}

		// Insert handler RVA
		iSection = FindSectionByRVA(CurrentRVA);
		iInsert = FindPosition(iSection, CurrentRVA);
		if (iSection == _UI16_MAX || iInsert == _UI32_MAX || iInsert == _UI32_MAX - 1) {
			_ReLibData.WarningCallback("Failed to insert handler RVA at 0x%08llx\n", NTHeaders.OptionalHeader.ImageBase + CurrentRVA);
		} else {
			Line ptr;
			ptr.Type = Pointer;
			ptr.OldRVA = CurrentRVA;
			ptr.Pointer.IsAbs = false;
			ptr.Pointer.RVA = HandlerRVA;
			Sections[iSection].Lines->Insert(iInsert, ptr);
		}
		
		// Scope table
		Vector<DWORD> TableRVAs;
		DWORD TableSize = ReadRVA<DWORD>(CurrentRVA + sizeof(DWORD));
		//if ((!EndingRVA && TableSize <= 100) || CurrentRVA + sizeof(DWORD) * 2 + sizeof(C_SCOPE_TABLE) * TableSize <= EndingRVA) {
		if (TableSize <= 10) {
			TableRVAs.Reserve(TableSize * 4);
			_ReLibData.LoggingCallback("Processing exception handler with %u table(s) (at 0x%p)\n", TableSize, NTHeaders.OptionalHeader.ImageBase + Func.UnwindData);
			for (int i = 0; i < TableSize * 4; i++) {
				TableRVAs.Push(ReadRVA<DWORD>(CurrentRVA + sizeof(DWORD) * (2 + i)));
			}
		}

		// Disassemble handler
		if (HandlerRVA && !DisasmRecursive(HandlerRVA)) return false;
			
		// Add scope table
		iSection = FindSectionByRVA(CurrentRVA);
		Line ptr;
		ptr.Type = Pointer;
		ptr.Pointer.IsAbs = false;
		for (int i = 0; i < TableRVAs.Size(); i++) {
			ptr.Pointer.RVA = TableRVAs[i];
			ptr.OldRVA = CurrentRVA + sizeof(DWORD) * (2 + i);
			if (TableRVAs[i] && !DisasmRecursive(TableRVAs[i])) {
				_ReLibData.WarningCallback("Invalid C_SCOPE_TABLE member at 0x%08llx\n", NTHeaders.OptionalHeader.ImageBase + ptr.OldRVA);
			} else {
				iInsert = FindPosition(iSection, ptr.OldRVA);
				if (iInsert != _UI32_MAX && iInsert != _UI32_MAX - 1) {
					Sections[iSection].Lines->Insert(iInsert, ptr);
				} else {
					_ReLibData.WarningCallback("Failed to insert C_SCOPE_TABLE member at 0x%08llx\n", NTHeaders.OptionalHeader.ImageBase + ptr.OldRVA);
				}
			}
		}
		TableRVAs.Release();
	}
	return true;
}

RELIB_EXPORT bool Asm::Disassemble(_In_ bool bDoFinalErrorCheck, _In_ bool bReturnIfFailed) {
	if (Status) {
		_ReLibData.ErrorCallback("Could not begin disassembly, as no binary is loaded (%hhd)\n", Status);
		return false;
	}

	// Calculate estimated size to disassemble
	for (int i = 0; i < NTHeaders.FileHeader.NumberOfSections; i++) {
		if (SectionHeaders[i].Characteristics & IMAGE_SCN_CNT_CODE || SectionHeaders[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			ToDo += SectionHeaders[i].SizeOfRawData;
		}
	}

	_ReLibData.LoggingCallback("Beginning disassembly\n");

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
			_ReLibData.WarningCallback("Failed to find position to insert line at 0x%p\n", NTHeaders.OptionalHeader.ImageBase + insert.OldRVA);
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
				_ReLibData.ErrorCallback("Failed to insert IAT!\n");
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
					_ReLibData.ErrorCallback("Failed to insert IAT!\n");
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
				_ReLibData.ErrorCallback("Failed to insert exports!\n");
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
				_ReLibData.ErrorCallback("Failed to insert exports!\n");
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
				_ReLibData.ErrorCallback("Failed to insert exports!\n");
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
	_ReLibData.LoggingCallback("Disassembling entry point\n");
	if (!DisasmRecursive(NTHeaders.OptionalHeader.AddressOfEntryPoint)) {
		_ReLibData.ErrorCallback("Failed to disassemble entry point (0x%p)\n", NTHeaders.OptionalHeader.ImageBase + NTHeaders.OptionalHeader.AddressOfEntryPoint);
		if (bReturnIfFailed) return false;
	} else {
		_ReLibData.LoggingCallback("Disassembled entry point (0x%p)\n", NTHeaders.OptionalHeader.ImageBase + NTHeaders.OptionalHeader.AddressOfEntryPoint);
	}

	// Disassemble TLS callbacks
	_ReLibData.LoggingCallback("Disassembling TLS callbacks\n");
	uint64_t* pCallbacks = GetTLSCallbacks();
	if (pCallbacks) {
		for (WORD i = 0; pCallbacks[i]; i++) {
			if (!DisasmRecursive(pCallbacks[i] - NTHeaders.OptionalHeader.ImageBase)) {
				_ReLibData.ErrorCallback("Failed to disassemble TLS callback at 0x%p\n", pCallbacks[i]);
				if (bReturnIfFailed) return false;
			} else {
				_ReLibData.LoggingCallback("Disassembled TLS callback (0x%p)\n", pCallbacks[i]);
			}
		}
	}

	// Disassemble exports
	_ReLibData.LoggingCallback("Disassembling exports\n");
	{
		Vector<DWORD> Exports = GetExportedSymbolRVAs();
		Vector<char*> ExportNames = GetExportedSymbolNames();
		for (int i = 0; i < Exports.Size(); i++) {
			if (!DisasmRecursive(Exports[i])) {
				_ReLibData.ErrorCallback("Failed to disassemble function at 0x%p\n", NTHeaders.OptionalHeader.ImageBase + Exports[i]);
				if (bReturnIfFailed) return false;
			} else {
				_ReLibData.LoggingCallback("Disassembled exported function \'%s\'\n", ExportNames[i]);
			}
		}
		Exports.Release();
		ExportNames.Release();
	}
	_ReLibData.LoggingCallback("Disassembled exports\n");

	// Disassemble exception dir
	_ReLibData.LoggingCallback("Disassembling exception directory\n");
	IMAGE_DATA_DIRECTORY ExcDataDir = NTHeaders.OptionalHeader.DataDirectory[3];
	if (ExcDataDir.VirtualAddress) {
		for (uint32_t i = 0; i < ExcDataDir.Size; i += sizeof(RUNTIME_FUNCTION)) {
			if (!CheckRuntimeFunction(ExcDataDir.VirtualAddress + i /* , i + sizeof(RUNTIME_FUNCTION) < ExcDataDir.Size ? ExcDataDir.VirtualAddress + i + sizeof(RUNTIME_FUNCTION) : 0 */)) {
				_ReLibData.ErrorCallback("Failed to check RUNTIME_FUNCTION at 0x%p\n", NTHeaders.OptionalHeader.ImageBase + ExcDataDir.VirtualAddress + i);
				if (bReturnIfFailed) return false;
			}
		}
	}
	_ReLibData.LoggingCallback("Disassembled exception directory\n");

	// Disassemble jump tables
	_ReLibData.LoggingCallback("Disassembling jump tables\n");
	{
		DWORD osize = JumpTables.Size();
		while (JumpTables.Size()) {
			DWORD dwJumpTable = JumpTables.Pop();
			if (!DisasmRecursive(dwJumpTable)) {
				_ReLibData.ErrorCallback("Failed to disassemble jump table at 0x%p\n", NTHeaders.OptionalHeader.ImageBase + dwJumpTable);
				if (bReturnIfFailed) return false;
			}
		}
		if (osize) _ReLibData.LoggingCallback("Disassembled %d switch cases\n", osize);
	}

	// Insert missing data + padding
	Line line;
	Vector<Line>* Lines = NULL;
	bool bExecutable;
	_ReLibData.LoggingCallback("Finalizing\n");
	for (int i = 0; i < Sections.Size(); i++) {
		Lines = Sections[i].Lines;
		RELIB_ASSERT(Lines != NULL);
		bExecutable = SectionHeaders[i].Characteristics & IMAGE_SCN_MEM_EXECUTE && ~SectionHeaders[i].Characteristics & IMAGE_SCN_MEM_WRITE;
		_ReLibData.LoggingCallback("Filling section %.8s (%llu lines)\n", SectionHeaders[i].Name, Lines->Size());

		// Incase section holds no lines
		if (!Lines->Size()) {
			if (bExecutable) {
				if (!DisasmRecursive(Sections[i].OldRVA)) {
					_ReLibData.ErrorCallback("Failed to disassemble section at 0x%p\n", NTHeaders.OptionalHeader.ImageBase + Sections[i].OldRVA);
					if (bReturnIfFailed) return false;
				}
			} else {
				line.Type = Embed;
				line.OldRVA = Sections[i].OldRVA;
				if (Sections[i].OldSize < SectionHeaders[i].SizeOfRawData) {
					line.Embed.Size = Sections[i].OldSize;
					Lines->Push(line);
					continue;
				}
				line.Embed.Size = SectionHeaders[i].SizeOfRawData;
				if (line.OldRVA && line.Embed.Size) Lines->Push(line);
				line.Type = Padding;
				line.OldRVA += line.Embed.Size;
				line.Padding.Size = Sections[i].OldSize - (line.OldRVA - Sections[i].OldRVA);
				if (line.OldRVA && line.Padding.Size) Lines->Push(line);
				continue;
			}
		}

		// Insert prepended data
		line.Type = Embed;
		if (Lines->At(0).OldRVA > Sections[i].OldRVA) {
			WORD dat = ReadRVA<WORD>(Sections[i].OldRVA);
			if (!bExecutable || !dat || dat == 0x9090 || !DisasmRecursive(Sections[i].OldRVA)) {
				line.OldRVA = Sections[i].OldRVA;
				line.Embed.Size = Lines->At(0).OldRVA - Sections[i].OldRVA;
				Lines->Insert(0, line);
			}
		} else if (Lines->At(0).OldRVA < Sections[i].OldRVA) {
			_ReLibData.WarningCallback("First line in section %d begins below the section (you should *hopefully* never see this)\n", i);
		}

		// Insert embedded data
		for (int j = 0; j < Lines->Size() - 1; j++) {
			line.OldRVA = Lines->At(j).OldRVA + GetLineSize(Lines->At(j));
			if (line.OldRVA < Lines->At(j + 1).OldRVA) {
				WORD dat = ReadRVA<WORD>(line.OldRVA);
				if (bExecutable && dat && dat != 0x9090 && DisasmRecursive(line.OldRVA)) {
					j--;
				} else {
					line.Embed.Size = Lines->At(j + 1).OldRVA - line.OldRVA;
					Lines->Insert(j + 1, line);
					j++;
				}
			}
		}

		// Insert ending data
		line.OldRVA = Lines->At(Lines->Size() - 1).OldRVA + GetLineSize(Lines->At(Lines->Size() - 1));
		if (line.OldRVA - Sections[i].OldRVA < SectionHeaders[i].SizeOfRawData && line.OldRVA - Sections[i].OldRVA < Sections[i].OldSize) {
			WORD dat = ReadRVA<WORD>(line.OldRVA);
			if (!bExecutable || !dat || dat == 0x9090 || !DisasmRecursive(line.OldRVA)) {
				line.Embed.Size = ((Sections[i].OldSize < SectionHeaders[i].SizeOfRawData) ? Sections[i].OldSize : SectionHeaders[i].SizeOfRawData) - (line.OldRVA - Sections[i].OldRVA);
				Lines->Push(line);
			}
		}

		// Insert padding
		line.Type = Padding;
		line.OldRVA = Lines->At(Lines->Size() - 1).OldRVA + GetLineSize(Lines->At(Lines->Size() - 1));
		line.Padding.Size = Sections[i].OldSize - (line.OldRVA - Sections[i].OldRVA);
		if (line.OldRVA && line.Padding.Size) Lines->Push(line);
	}
	_ReLibData.LoggingCallback("Finished disassembly\n");

	// Error check
	if (bDoFinalErrorCheck) {
		for (size_t i = 0; i < Sections.Size(); i++) {
			if (Sections[i].OldRVA > NTHeaders.OptionalHeader.SizeOfImage) {
				_ReLibData.ErrorCallback("Validation failed, 0x%p > 0x%p\n", NTHeaders.OptionalHeader.ImageBase + Sections[i].OldRVA, NTHeaders.OptionalHeader.ImageBase + NTHeaders.OptionalHeader.SizeOfImage);
				return false;
			}
			Vector<Line>* Lines = Sections[i].Lines;
			RELIB_ASSERT(Lines != NULL);
			for (size_t j = 0; j < Lines->Size(); j++) {
				if (Lines->At(j).OldRVA > NTHeaders.OptionalHeader.SizeOfImage) {
					_ReLibData.ErrorCallback("Validation failed, 0x%p > 0x%p\n", NTHeaders.OptionalHeader.ImageBase + Lines->At(j).OldRVA, NTHeaders.OptionalHeader.ImageBase + NTHeaders.OptionalHeader.SizeOfImage);
					return false;
				}
				if (j < Lines->Size() - 1 && Lines->At(j).OldRVA + GetLineSize(Lines->At(j)) != Lines->At(j + 1).OldRVA) {
					_ReLibData.ErrorCallback("Validation failed, 0x%p + %u != 0x%p\n", NTHeaders.OptionalHeader.ImageBase + Lines->At(j).OldRVA, GetLineSize(Lines->At(j)), NTHeaders.OptionalHeader.ImageBase + Lines->At(j + 1).OldRVA);
					return false;
				}
			}
		}
	}
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
		case ZYDIS_MNEMONIC_MOVSB: return !pAsm->movsb();
		case ZYDIS_MNEMONIC_MOVSW: return !pAsm->movsw();
		case ZYDIS_MNEMONIC_MOVSD: return !pAsm->movsd();
		case ZYDIS_MNEMONIC_MOVSQ: return !pAsm->movsq();
		case ZYDIS_MNEMONIC_STOSB: return !pAsm->stosb();
		case ZYDIS_MNEMONIC_STOSW: return !pAsm->stosw();
		case ZYDIS_MNEMONIC_STOSD: return !pAsm->stosd();
		case ZYDIS_MNEMONIC_STOSQ: return !pAsm->stosq();
		}
	}

	// Convert mnemonic
	InstId mnem = ZydisToAsmJit::Mnemonics[pLine->Decoded.Instruction.mnemonic];
	if (!mnem) {
		_ReLibData.ErrorCallback("Failed to translate mnemonic: %d\n", pLine->Decoded.Instruction.mnemonic);
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
		_ReLibData.WarningCallback("Unable to process all operands\n");
	}

	return !pAsm->_emit(mnem, ops[0], ops[1], ops[2], &ops[3]);
}

RELIB_EXPORT bool Asm::Assemble() {
	// Setup
	if (!Sections.Size()) return false;
	if (!pAsm) {
		_ReLibData.ErrorCallback("Assembler not set\n");
		return false;
	}
	_ReLibData.LoggingCallback("Assembling\n");
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
	pAsm->dq(0, SectionHeaders[0].VirtualAddress / 8);
	for (DWORD SecIndex = 0; SecIndex < Sections.Size(); SecIndex++) {
		// Prepare next section
		AsmSection section = Sections[SecIndex];
		pLines = section.Lines;
		RELIB_ASSERT(pLines != NULL);
		section.NewRVA = pAsm->offset();
		DWORD rva = section.NewRVA;
		section.NewRawSize = 0;
		section.NewVirtualSize = 0;

		// Assemble lines
		for (int i = 0; i < pLines->Size(); i++) {
			fProgress = (float)i / (float)pLines->Size();
			line = pLines->At(i);
			line.NewRVA = rva;
			pLines->operator[](i) = line;
			size_t off = pAsm->offset();

			switch (line.Type) {
			case Decoded: {
				// Calculate referenced address
				uint64_t refs = 0;
				Label ah;
				ZydisRegister SubIndex = ZYDIS_REGISTER_NONE;
				if (IsInstructionCF(line.Decoded.Instruction.mnemonic) && line.Decoded.Operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
					ZydisDecodedInstruction inst = line.Decoded.Instruction;
					ZydisDecodedOperand op = line.Decoded.Operands[0];
					op.imm.is_relative = true;
					op.imm.is_signed = true;
					if (ZYAN_FAILED(ZydisCalcAbsoluteAddress(&inst, &op, NTHeaders.OptionalHeader.ImageBase + line.OldRVA, &refs))) {
						_ReLibData.WarningCallback("Failed to calculate absolute address at 0x%p\n", NTHeaders.OptionalHeader.ImageBase + line.OldRVA);
					}
				} else if (JumpTableIndexers.Includes(line.OldRVA)) {
					SubIndex = line.Decoded.Operands[0].reg.value;
					refs = line.Decoded.Operands[1].mem.disp.value + NTHeaders.OptionalHeader.ImageBase;
					line.Decoded.Operands[1].mem.base = SubIndex;
					line.Decoded.Operands[1].mem.disp.value = 0;
					line.Decoded.Operands[1].mem.disp.has_displacement = 0;
			 	} else {
					for (int i = 0; i < line.Decoded.Instruction.operand_count_visible; i++) {
						if (line.Decoded.Operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY && (line.Decoded.Operands[i].mem.base == ZYDIS_REGISTER_RIP || line.Decoded.Operands[i].mem.index == ZYDIS_REGISTER_RIP)) {
							ZydisDecodedInstruction inst = line.Decoded.Instruction;
							ZydisDecodedOperand op = line.Decoded.Operands[i];
							if (ZYAN_FAILED(ZydisCalcAbsoluteAddress(&inst, &op, NTHeaders.OptionalHeader.ImageBase + line.OldRVA, &refs))) {
								_ReLibData.WarningCallback("Failed to calculate absolute address at 0x%p\n", NTHeaders.OptionalHeader.ImageBase + line.OldRVA);
							}
							break;
						}
					}
				}

				// Find label for reference
				if (refs) {
					int loc = XREFs.Find(refs - NTHeaders.OptionalHeader.ImageBase);
					if (loc < 0) {
						XREFs.Push(refs - NTHeaders.OptionalHeader.ImageBase);
						ah = pAsm->newLabel();
						XREFLabels.Push(ah);
					} else {
						ah = XREFLabels[loc];
					}
				}

				// Replace some jump table stuff
				if (SubIndex != ZYDIS_REGISTER_NONE) {
					Gpq base = reinterpret_cast<Gp*>(&ZydisToAsmJit::Registers[SubIndex])->r64();
					Gpq index = reinterpret_cast<Gp*>(&ZydisToAsmJit::Registers[line.Decoded.Operands[1].mem.index])->r64();
					pAsm->lea(base, ptr(ah));
					int shift = line.Decoded.Operands[1].mem.scale;
					shift = shift == 8 ? 3 : shift / 2;
					pAsm->shl(index, shift);
					pAsm->add(base, index);
					pAsm->shr(index, shift);
					line.Decoded.Operands[1].mem.index = ZYDIS_REGISTER_NONE;
					line.Decoded.Operands[1].mem.scale = 1;
				}

				// Encode
				if (!FromDis(&line, refs ? &ah : NULL)) {
					XREFs.Release();
					XREFLabels.Release();
					LinkLater.Release();
					LinkLaterOffsets.Release();
					_ReLibData.ErrorCallback("Failed to assemble instruction at 0x%p\n", NTHeaders.OptionalHeader.ImageBase + line.OldRVA);
					return false;
				}
				break;
			}
			case Embed: {
				Buffer buf;
				buf.Allocate(line.Embed.Size);
				ReadRVA(line.OldRVA, buf.Data(), buf.Size());
				pAsm->embed(buf.Data(), buf.Size());
				buf.Release();
				break;
			}
			case RawInsert:
				pAsm->embed(line.RawInsert.Data(), line.RawInsert.Size());
				break;
			case Padding:
				section.NewVirtualSize += line.Padding.Size;
				pAsm->db(0, line.Padding.Size);
				if (i < pLines->Size() - 1) {
					_ReLibData.ErrorCallback("Ran into padding in the middle of a section\n");
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
		section.NewRawSize = pAsm->offset() - section.NewRVA;
		section.NewRawSize -= section.NewVirtualSize;
		section.NewVirtualSize += section.NewRawSize;
		if (pAsm->offset() % NTHeaders.OptionalHeader.SectionAlignment) {
			pAsm->db(0, NTHeaders.OptionalHeader.SectionAlignment - pAsm->offset() % NTHeaders.OptionalHeader.SectionAlignment);
		}
		Sections[SecIndex] = section;
	}

	// Link
	fProgress = 0.f;
	_ReLibData.LoggingCallback("Linking\n");
	if (LinkLater.Size() != LinkLaterOffsets.Size()) {
		_ReLibData.ErrorCallback("This should never happen (LinkLater.Size() != LinkLaterOffsets.Size())\n");
		LinkLater.Release();
		LinkLaterOffsets.Release();
		XREFs.Release();
		XREFLabels.Release();
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
			_ReLibData.ErrorCallback("This also should never happen (LinkLater[i].Type != JumpTable && LinkLater[i].Type != Pointer)\n");
			LinkLater.Release();
			LinkLaterOffsets.Release();
			XREFs.Release();
			XREFLabels.Release();
			return false;
		}
	}
	LinkLater.Release();
	LinkLaterOffsets.Release();
	if (XREFs.Size() != XREFLabels.Size()) {
		_ReLibData.ErrorCallback("This should never happen part 2 (XREFs.Size() != XREFLabels.Size())\n");
		return false;
	}
	for (int i = 0; i < XREFs.Size(); i++) {
		pAsm->code()->bindLabel(XREFLabels[i], pAsm->code()->textSection()->id(), TranslateOldAddress(XREFs[i]));
	}
	XREFs.Release();
	XREFLabels.Release();

	// Translate known addresses
	_ReLibData.LoggingCallback("Translating addresses\n");
	for (int i = 0; i < 16; i++) {
		if (i == 5) continue;
		NTHeaders.OptionalHeader.DataDirectory[i].VirtualAddress = TranslateOldAddress(NTHeaders.OptionalHeader.DataDirectory[i].VirtualAddress);
		if (NTHeaders.OptionalHeader.DataDirectory[i].VirtualAddress == _UI32_MAX) {
			_ReLibData.WarningCallback("Failed to translate data directory %d\n", i);
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
	NTHeaders.OptionalHeader.DataDirectory[5].Size = relocs.Size();

	// Copy data
	_ReLibData.LoggingCallback("Finalizing\n");
	pAsm->code()->flatten();
	pAsm->code()->relocateToBase(NTHeaders.OptionalHeader.ImageBase);
	_ReLibData.LoggingCallback("Assembled code has %d sections, and has %d relocations\n", pAsm->code()->sectionCount(), pAsm->code()->hasRelocEntries() ? pAsm->code()->relocEntries().size() : 0);
	if (pAsm->code()->hasUnresolvedLinks()) pAsm->code()->resolveUnresolvedLinks();
	if (pAsm->code()->hasUnresolvedLinks()) _ReLibData.WarningCallback("Assembled code has %d unsolved links\n", pAsm->code()->unresolvedLinkCount());
	for (int i = 0; i < NTHeaders.FileHeader.NumberOfSections; i++) {
		SectionData[i].Release();
		Buffer buf;
		SectionData[i] = buf;
		if (!Sections[i].NewVirtualSize && !Sections[i].NewRawSize) {
			DeleteSection(i);
			i--;
		}
		buf.Allocate(Sections[i].NewRawSize);
		if (pAsm->code()->textSection()->buffer().size() < Sections[i].NewRVA + buf.Size()) {
			_ReLibData.ErrorCallback("Failed to read assembled code (size: 0x%p, expected: 0x%p)\n", pAsm->code()->textSection()->buffer().size(), Sections[i].NewRVA + buf.Size());
			return false;
		}
		memcpy_s(buf.Data(), buf.Size(), pAsm->code()->textSection()->buffer().data() + Sections[i].NewRVA, buf.Size());
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
	RelocHeader.Misc.VirtualSize = RelocHeader.SizeOfRawData = relocs.Size();
	RelocHeader.VirtualAddress = SectionHeaders[SectionHeaders.Size() - 1].VirtualAddress + SectionHeaders[SectionHeaders.Size() - 1].Misc.VirtualSize;
	RelocHeader.VirtualAddress += (RelocHeader.VirtualAddress % NTHeaders.OptionalHeader.SectionAlignment) ? NTHeaders.OptionalHeader.SectionAlignment - (RelocHeader.VirtualAddress % NTHeaders.OptionalHeader.SectionAlignment) : 0;
	NTHeaders.OptionalHeader.DataDirectory[5].VirtualAddress = RelocHeader.VirtualAddress;
	RelocHeader.Characteristics = IMAGE_SCN_MEM_READ;
	memcpy_s(RelocHeader.Name, 8, ".reloc\0", 8);
	SectionHeaders.Push(RelocHeader);
	SectionData.Push(relocs);
	NTHeaders.FileHeader.NumberOfSections++;

	// Fix function ranges
	for (int i = 0; i < FunctionRanges.Size(); i++) {
		FunctionRange range = FunctionRanges[i];
		range.dwEntry = TranslateOldAddress(range.dwEntry);
		
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
	_ReLibData.LoggingCallback("Finished assembly\n");
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
	_ReLibData.LoggingCallback("Stripping PE\n");
	// Debug directory
	if (NTHeaders.OptionalHeader.DataDirectory[6].Size && NTHeaders.OptionalHeader.DataDirectory[6].VirtualAddress) {
		DWORD dwSize = NTHeaders.OptionalHeader.DataDirectory[6].Size;
		for (int i = 0, n = dwSize / sizeof(IMAGE_DEBUG_DIRECTORY); i < n; i++) {
			IMAGE_DEBUG_DIRECTORY debug = ReadRVA<IMAGE_DEBUG_DIRECTORY>(NTHeaders.OptionalHeader.DataDirectory[6].VirtualAddress + sizeof(IMAGE_DEBUG_DIRECTORY) * i);
			RemoveData(debug.AddressOfRawData, debug.SizeOfData);
			dwSize += debug.SizeOfData;
		}
		RemoveData(NTHeaders.OptionalHeader.DataDirectory[6].VirtualAddress, NTHeaders.OptionalHeader.DataDirectory[6].Size);
		_ReLibData.LoggingCallback("Removed debug directory (%#x bytes)\n", dwSize);
		NTHeaders.OptionalHeader.DataDirectory[6].VirtualAddress = NTHeaders.OptionalHeader.DataDirectory[6].Size = 0;
	}

	// Symbol table
	if (NTHeaders.FileHeader.PointerToSymbolTable && NTHeaders.FileHeader.PointerToSymbolTable < OverlayOffset) {
		_ReLibData.WarningCallback("Stripping non-overlay symbols, this is untested code!\n");
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
							_ReLibData.LoggingCallback("Unloaded section %.8s (%s)\n", SectionHeaders[sym.SectionNumber - 1].Name, str);
						}
					}
					str[7] = bak;
				}
			}
		}
		RemoveData(rva, end - rva);
		_ReLibData.LoggingCallback("Removed %d symbols\n", NTHeaders.FileHeader.NumberOfSymbols);
	}

	// Overlay
	if (NTHeaders.FileHeader.PointerToSymbolTable >= OverlayOffset) {
		IMAGE_SYMBOL* pSyms = reinterpret_cast<IMAGE_SYMBOL*>(Overlay.Data() + (NTHeaders.FileHeader.PointerToSymbolTable - OverlayOffset));
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
							_ReLibData.LoggingCallback("Unloaded section %.8s (%s)\n", SectionHeaders[pSyms[i].SectionNumber - 1].Name, str);
						}
					}
					str[7] = bak;
				}
			}
		}
		_ReLibData.LoggingCallback("Removed %d symbols\n", NTHeaders.FileHeader.NumberOfSymbols);
	}
	DiscardOverlay();

	// Useless sections
	for (WORD i = 0; i < NTHeaders.FileHeader.NumberOfSections; i++) {
		if (!SectionHeaders[i].VirtualAddress || !SectionHeaders[i].Misc.VirtualSize) {
			_ReLibData.LoggingCallback("Removed section %.8s\n", SectionHeaders[i].Name);
			DeleteSection(i);
			i--;
		}
	}
	NTHeaders.FileHeader.PointerToSymbolTable = 0;
	NTHeaders.FileHeader.NumberOfSymbols = 0;
	NTHeaders.FileHeader.Characteristics |= IMAGE_FILE_LOCAL_SYMS_STRIPPED | IMAGE_FILE_DEBUG_STRIPPED;

	_ReLibData.LoggingCallback("Stripped\n");
	return true;
}

RELIB_EXPORT void Asm::DeleteSection(_In_ WORD wIndex) {
	Sections.Remove(wIndex);
	PE::DeleteSection(wIndex);
}

RELIB_EXPORT DWORD Asm::GetAssembledSize(_In_ DWORD SectionIndex) {
	DWORD dwSize = 0;
	Vector<Line>* Lines = Sections[SectionIndex].Lines;
	RELIB_ASSERT(Lines != NULL);
	for (DWORD i = 0; i < Lines->Size(); i++) {
		dwSize += GetLineSize(Lines->At(i));
	}
	return dwSize;
}

RELIB_EXPORT void Asm::InsertLine(_In_ DWORD SectionIndex, _In_ DWORD LineIndex, _In_ Line line) {
	if (SectionIndex >= Sections.Size()) return;
	RELIB_ASSERT(Sections[SectionIndex].Lines != NULL);
	if (LineIndex > Sections[SectionIndex].Lines->Size()) return;
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
		_ReLibData.ErrorCallback("Failed to translate address 0x%p\n", NTHeaders.OptionalHeader.ImageBase + dwRVA);
		return 0;
	}
	RELIB_ASSERT(Sections[SecIndex].Lines != NULL);
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
		_ReLibData.WarningCallback("Failed to remove data at range 0x%p - 0x%p\n", NTHeaders.OptionalHeader.ImageBase + dwRVA, NTHeaders.OptionalHeader.ImageBase + dwRVA + dwSize);
		return;
	}

	Line data = Sections[sec].Lines->At(i);
	if (data.Type != Embed || data.OldRVA > dwRVA || data.OldRVA + GetLineSize(data) < dwRVA + dwSize) {
		_ReLibData.WarningCallback("Failed to remove data at range 0x%p - 0x%p (this version can be fixed later)\n", NTHeaders.OptionalHeader.ImageBase + dwRVA, NTHeaders.OptionalHeader.ImageBase + dwRVA + dwSize);
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

RELIB_EXPORT Vector<FunctionRange> Asm::GetFunctionRanges() {
	return FunctionRanges;
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
		return line.RawInsert.Size();
	case Pointer:
		return (line.Pointer.IsAbs ? sizeof(uint64_t) : sizeof(DWORD));
	}
	_ReLibData.WarningCallback("Failed to calculate length of instruction (unknown type), type value of %hhd\n", line.Type);
	return 0;
}

RELIB_EXPORT Vector<AsmSection> Asm::GetSections() {
	return Sections;
}