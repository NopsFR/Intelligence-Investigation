// Reverse-engineering reference: registers, common instructions, calling
// conventions, and syscalls. Hand-authored from public ISA documentation
// (Intel/AMD manuals, ARM Architecture Reference Manual, Linux syscall
// table) — nothing here is fetched or executed.

export interface RegisterEntry {
  name: string;
  width: string;
  purpose: string;
}

export const X86_64_REGISTERS: RegisterEntry[] = [
  { name: "RAX / EAX / AX / AL", width: "64/32/16/8", purpose: "Accumulator — return value, arithmetic" },
  { name: "RBX / EBX / BX / BL", width: "64/32/16/8", purpose: "Base — callee-saved general purpose" },
  { name: "RCX / ECX / CX / CL", width: "64/32/16/8", purpose: "Counter — loop counter, 4th arg (SysV) / 1st arg (MS x64)" },
  { name: "RDX / EDX / DX / DL", width: "64/32/16/8", purpose: "Data — 3rd arg (SysV) / 2nd arg (MS x64), I/O" },
  { name: "RSI / ESI / SI / SIL", width: "64/32/16/8", purpose: "Source index — 2nd arg (SysV), string-op source" },
  { name: "RDI / EDI / DI / DIL", width: "64/32/16/8", purpose: "Destination index — 1st arg (SysV), string-op dest" },
  { name: "RBP / EBP / BP / BPL", width: "64/32/16/8", purpose: "Base pointer — stack frame base (callee-saved)" },
  { name: "RSP / ESP / SP / SPL", width: "64/32/16/8", purpose: "Stack pointer — top of the call stack" },
  { name: "R8–R15", width: "64/32/16/8", purpose: "Additional general-purpose registers (5th–6th args in MS x64: R8, R9)" },
  { name: "RIP", width: "64", purpose: "Instruction pointer — not directly writable; changed by control-flow instructions" },
  { name: "RFLAGS", width: "64", purpose: "Status flags: ZF (zero), CF (carry), SF (sign), OF (overflow), etc." },
  { name: "XMM0–XMM15", width: "128", purpose: "SSE floating-point / vector registers; XMM0–XMM3 (SysV) or XMM0–XMM3 (MS x64) pass float args" },
];

export const ARM64_REGISTERS: RegisterEntry[] = [
  { name: "X0–X7", width: "64 (W0–W7: 32)", purpose: "Argument/result registers (AAPCS64)" },
  { name: "X8", width: "64", purpose: "Indirect result register / Linux syscall number (in some ABIs)" },
  { name: "X9–X15", width: "64", purpose: "Caller-saved temporary registers" },
  { name: "X16 / X17 (IP0/IP1)", width: "64", purpose: "Intra-procedure-call scratch registers, used by the linker for veneers" },
  { name: "X18", width: "64", purpose: "Platform register — reserved on some platforms (e.g. Windows, iOS)" },
  { name: "X19–X28", width: "64", purpose: "Callee-saved registers" },
  { name: "X29 (FP)", width: "64", purpose: "Frame pointer" },
  { name: "X30 (LR)", width: "64", purpose: "Link register — holds the return address after BL" },
  { name: "SP", width: "64", purpose: "Stack pointer" },
  { name: "PC", width: "64", purpose: "Program counter — not directly accessible as a general register" },
  { name: "XZR / WZR", width: "64/32", purpose: "Zero register — reads as 0, writes are discarded" },
  { name: "V0–V31", width: "128", purpose: "NEON/floating-point vector registers" },
];

export interface InstructionEntry {
  mnemonic: string;
  syntax: string;
  description: string;
  flags?: string;
  example?: string;
}

export const X86_64_INSTRUCTIONS: InstructionEntry[] = [
  { mnemonic: "MOV", syntax: "MOV dst, src", description: "Copies src into dst. Does not affect flags." },
  { mnemonic: "LEA", syntax: "LEA dst, [mem]", description: "Loads the computed address of a memory operand (not its value) into dst — often used for arithmetic, not just addressing." },
  { mnemonic: "PUSH / POP", syntax: "PUSH src / POP dst", description: "Decrements RSP and stores src (PUSH), or loads from [RSP] into dst and increments RSP (POP)." },
  { mnemonic: "ADD / SUB", syntax: "ADD dst, src", description: "Adds/subtracts src to/from dst.", flags: "Sets ZF, CF, SF, OF" },
  { mnemonic: "IMUL / IDIV", syntax: "IMUL src / IDIV src", description: "Signed multiply/divide, implicitly using RAX:RDX." },
  { mnemonic: "AND / OR / XOR", syntax: "XOR dst, src", description: "Bitwise operations. XOR reg, reg (same register) is a common idiom for zeroing a register.", flags: "Sets ZF, SF; clears CF, OF" },
  { mnemonic: "CMP", syntax: "CMP a, b", description: "Computes a - b to set flags, discarding the result — used before a conditional jump.", flags: "Sets ZF, CF, SF, OF" },
  { mnemonic: "TEST", syntax: "TEST a, b", description: "Computes a AND b to set flags, discarding the result — TEST reg, reg is a common idiom to check for zero/negative.", flags: "Sets ZF, SF; clears CF, OF" },
  { mnemonic: "JMP", syntax: "JMP target", description: "Unconditional jump." },
  { mnemonic: "JE / JZ", syntax: "JE target", description: "Jump if ZF is set (equal / zero)." },
  { mnemonic: "JNE / JNZ", syntax: "JNE target", description: "Jump if ZF is clear (not equal / not zero)." },
  { mnemonic: "JG / JL / JGE / JLE", syntax: "JG target", description: "Jump on signed greater/less/greater-or-equal/less-or-equal, based on SF/OF/ZF." },
  { mnemonic: "JA / JB", syntax: "JA target", description: "Jump on unsigned above/below, based on CF/ZF." },
  { mnemonic: "CALL / RET", syntax: "CALL target / RET", description: "CALL pushes the return address and jumps; RET pops the return address and jumps to it." },
  { mnemonic: "NOP", syntax: "NOP", description: "No operation — often padding, or a marker left by a patched-out instruction." },
  { mnemonic: "SYSCALL", syntax: "SYSCALL", description: "Linux/BSD: transfers control to the kernel using the number in RAX and args in RDI, RSI, RDX, R10, R8, R9." },
  { mnemonic: "INT 0x80", syntax: "INT 0x80", description: "Legacy 32-bit Linux syscall interrupt — number in EAX, args in EBX, ECX, EDX, ESI, EDI, EBP." },
  { mnemonic: "REP MOVSB/STOSB", syntax: "REP MOVSB", description: "Repeats a string instruction RCX times — REP MOVSB is a common memcpy-equivalent idiom, REP STOSB a memset-equivalent." },
  { mnemonic: "PUSHAD / POPAD (x86)", syntax: "PUSHAD / POPAD", description: "Saves/restores all general-purpose registers at once — a strong signal of a manual calling-convention bridge or shellcode stub." },
];

export const ARM64_INSTRUCTIONS: InstructionEntry[] = [
  { mnemonic: "MOV", syntax: "MOV Xd, Xn", description: "Copies a register or moves an immediate into a register." },
  { mnemonic: "LDR / STR", syntax: "LDR Xt, [Xn, #imm]", description: "Load/store a register from/to memory, with optional immediate or register offset." },
  { mnemonic: "ADD / SUB", syntax: "ADD Xd, Xn, Xm", description: "Adds/subtracts registers or an immediate; ADD/SUB with SP is used for stack frame setup." },
  { mnemonic: "CMP", syntax: "CMP Xn, Xm", description: "Alias for SUBS XZR, Xn, Xm — sets flags, discards the result." },
  { mnemonic: "B / BL", syntax: "B label / BL label", description: "Branch (B) or branch-with-link (BL, saves return address in X30/LR)." },
  { mnemonic: "B.cond", syntax: "B.EQ label", description: "Conditional branch based on the NZCV flags (EQ, NE, GT, LT, GE, LE, ...)." },
  { mnemonic: "CBZ / CBNZ", syntax: "CBZ Xn, label", description: "Branch if a register is (not) zero, without needing a prior CMP." },
  { mnemonic: "BR / BLR", syntax: "BR Xn / BLR Xn", description: "Branch (with link) to an address held in a register — used for indirect calls/jumps, and pointer-authentication bypasses target these." },
  { mnemonic: "RET", syntax: "RET", description: "Return — branches to the address in X30 (LR) by default." },
  { mnemonic: "SVC", syntax: "SVC #0", description: "Supervisor call — Linux AArch64 syscall, number in X8, args in X0–X5." },
  { mnemonic: "STP / LDP", syntax: "STP X29, X30, [SP, #-16]!", description: "Store/load a pair of registers — the canonical AArch64 function prologue saves FP and LR this way." },
  { mnemonic: "ADRP / ADD", syntax: "ADRP Xd, page; ADD Xd, Xd, #off", description: "Computes a PC-relative address in two steps — the standard idiom for loading a global/string address." },
];

export interface CallingConvention {
  name: string;
  platforms: string;
  intArgs: string;
  floatArgs: string;
  returnReg: string;
  callerSaved: string;
  calleeSaved: string;
  stackCleanup: string;
}

export const CALLING_CONVENTIONS: CallingConvention[] = [
  {
    name: "System V AMD64 ABI",
    platforms: "Linux, macOS, BSD (x86-64)",
    intArgs: "RDI, RSI, RDX, RCX, R8, R9 (then stack)",
    floatArgs: "XMM0–XMM7",
    returnReg: "RAX (RDX:RAX for 128-bit)",
    callerSaved: "RAX, RCX, RDX, RSI, RDI, R8–R11",
    calleeSaved: "RBX, RBP, R12–R15",
    stackCleanup: "Caller cleans up the stack",
  },
  {
    name: "Microsoft x64",
    platforms: "Windows (x86-64)",
    intArgs: "RCX, RDX, R8, R9 (then stack)",
    floatArgs: "XMM0–XMM3 (shares slot count with integer args)",
    returnReg: "RAX",
    callerSaved: "RAX, RCX, RDX, R8–R11",
    calleeSaved: "RBX, RBP, RDI, RSI, RSP, R12–R15",
    stackCleanup: "Caller cleans up the stack; 32-byte \"shadow space\" reserved for callee",
  },
  {
    name: "cdecl",
    platforms: "x86 (32-bit), C default",
    intArgs: "Stack only, pushed right-to-left",
    floatArgs: "Stack (or x87 FPU stack for return)",
    returnReg: "EAX",
    callerSaved: "EAX, ECX, EDX",
    calleeSaved: "EBX, EBP, ESI, EDI",
    stackCleanup: "Caller cleans up the stack",
  },
  {
    name: "stdcall",
    platforms: "x86 (32-bit), Win32 API",
    intArgs: "Stack only, pushed right-to-left",
    floatArgs: "Stack",
    returnReg: "EAX",
    callerSaved: "EAX, ECX, EDX",
    calleeSaved: "EBX, EBP, ESI, EDI",
    stackCleanup: "Callee cleans up the stack (RET n)",
  },
  {
    name: "AAPCS64",
    platforms: "ARM64 / AArch64 (Linux, Android, iOS, Windows)",
    intArgs: "X0–X7 (then stack)",
    floatArgs: "V0–V7",
    returnReg: "X0 (X1 for the high half of 128-bit)",
    callerSaved: "X0–X18",
    calleeSaved: "X19–X28, X29 (FP), X30 (LR)",
    stackCleanup: "Caller cleans up the stack; SP must be 16-byte aligned at a public interface",
  },
];

export interface SyscallEntry {
  number: number;
  name: string;
  args: string;
}

// Linux x86-64 syscall table — a curated subset covering the syscalls most
// relevant to malware/behavioral analysis, not the full table (~450 entries).
export const LINUX_X86_64_SYSCALLS: SyscallEntry[] = [
  { number: 0, name: "read", args: "fd, buf, count" },
  { number: 1, name: "write", args: "fd, buf, count" },
  { number: 2, name: "open", args: "filename, flags, mode" },
  { number: 3, name: "close", args: "fd" },
  { number: 9, name: "mmap", args: "addr, len, prot, flags, fd, off" },
  { number: 10, name: "mprotect", args: "addr, len, prot" },
  { number: 11, name: "munmap", args: "addr, len" },
  { number: 12, name: "brk", args: "addr" },
  { number: 21, name: "access", args: "filename, mode" },
  { number: 22, name: "pipe", args: "fildes[2]" },
  { number: 39, name: "getpid", args: "—" },
  { number: 41, name: "socket", args: "family, type, protocol" },
  { number: 42, name: "connect", args: "fd, addr, addrlen" },
  { number: 43, name: "accept", args: "fd, addr, addrlen" },
  { number: 44, name: "sendto", args: "fd, buf, len, flags, addr, addrlen" },
  { number: 45, name: "recvfrom", args: "fd, buf, len, flags, addr, addrlen" },
  { number: 49, name: "bind", args: "fd, addr, addrlen" },
  { number: 50, name: "listen", args: "fd, backlog" },
  { number: 56, name: "clone", args: "flags, stack, parent_tid, child_tid, tls" },
  { number: 57, name: "fork", args: "—" },
  { number: 59, name: "execve", args: "filename, argv, envp" },
  { number: 60, name: "exit", args: "status" },
  { number: 62, name: "kill", args: "pid, sig" },
  { number: 82, name: "rename", args: "oldpath, newpath" },
  { number: 83, name: "mkdir", args: "pathname, mode" },
  { number: 86, name: "link", args: "oldpath, newpath" },
  { number: 87, name: "unlink", args: "pathname" },
  { number: 101, name: "ptrace", args: "request, pid, addr, data" },
  { number: 157, name: "prctl", args: "option, arg2, arg3, arg4, arg5" },
  { number: 165, name: "mount", args: "source, target, fstype, flags, data" },
  { number: 231, name: "exit_group", args: "status" },
  { number: 257, name: "openat", args: "dirfd, pathname, flags, mode" },
  { number: 435, name: "clone3", args: "cl_args, size" },
];

export const LINUX_AARCH64_SYSCALL_NOTE =
  "AArch64 Linux uses a unified syscall table (no legacy int-80 split): the syscall number goes in X8, args in X0–X5, and numbers mostly match the x86-64 generic table above except where noted in the kernel's arch/arm64/include syscall tables.";
