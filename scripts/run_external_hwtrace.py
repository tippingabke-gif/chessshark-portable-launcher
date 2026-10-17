#!/usr/bin/env python3
"""Observe a 32-bit WOW64 process with external debug registers.

This runner deliberately does not call DebugActiveProcess/DebugBreakProcess and
does not create a debug object.  It starts the no-UAC observation copy normally,
finds the unpacked 0x793000-byte stage, installs x86 execute breakpoints through
Wow64SetThreadContext, and registers a tiny x86 VEH in the target.  The VEH
records a STATUS_SINGLE_STEP context in a remote read-only-to-us log page and
returns EXCEPTION_CONTINUE_EXECUTION after clearing the local DR7 enable bits.

The remote page is transient process memory; the executable on disk is never
written.  The code is intentionally self-contained because this host has no
32-bit compiler.  It is useful as an observation aid, not as a patcher.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import struct
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

K = ctypes.WinDLL("kernel32", use_last_error=True)
NT = ctypes.WinDLL("ntdll", use_last_error=True)

# Process/thread/memory constants.
PROCESS_ALL_ACCESS = 0x001F0FFF
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_CREATE_THREAD = 0x0002
THREAD_SUSPEND_RESUME = 0x0002
THREAD_GET_CONTEXT = 0x0008
THREAD_SET_CONTEXT = 0x0010
THREAD_QUERY_INFORMATION = 0x0040
THREAD_QUERY_LIMITED_INFORMATION = 0x0800
TH32CS_SNAPTHREAD = 0x00000004
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
WAIT_OBJECT_0 = 0
INFINITE = 0xFFFFFFFF
WOW64_CONTEXT_DEBUG_REGISTERS = 0x00010010
WOW64_CONTEXT_FULL = 0x00010007
EXCEPTION_SINGLE_STEP = 0x80000004

TARGET_DEFAULT = Path("ChessShark.exe")
HELPER_DEFAULT = Path(__file__).resolve().parent / "chessshark_ui_helper_nofallback.py"
OUT_DEFAULT = Path(__file__).resolve().parent / "external_hwtrace"
STAGE_SIZE = 0x793000

# Candidate RVAs used by the prior static/runtime map.  The script accepts a
# replacement list so a fresh stage map can be tested without editing code.
DEFAULT_RVAS = {
    "EP_RegKeyStatus_body": 0x66E66B,
    "EP_RegCheckKeyA_body": 0x68791C,
    "EP_RegCheckKeyW_body": 0x68A1FA,
    "EP_RegLoadAndCheckKey_body": 0x670B0F,
}


class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD), ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD), ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


class FLOAT_SAVE(ctypes.Structure):
    _fields_ = [
        ("ControlWord", wintypes.DWORD), ("StatusWord", wintypes.DWORD),
        ("TagWord", wintypes.DWORD), ("ErrorOffset", wintypes.DWORD),
        ("ErrorSelector", wintypes.DWORD), ("DataOffset", wintypes.DWORD),
        ("DataSelector", wintypes.DWORD), ("RegisterArea", wintypes.BYTE * 80),
        ("Cr0NpxState", wintypes.DWORD),
    ]


class WOW64_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("ContextFlags", wintypes.DWORD),
        ("Dr0", wintypes.DWORD), ("Dr1", wintypes.DWORD),
        ("Dr2", wintypes.DWORD), ("Dr3", wintypes.DWORD),
        ("Dr6", wintypes.DWORD), ("Dr7", wintypes.DWORD),
        ("FloatSave", FLOAT_SAVE),
        ("SegGs", wintypes.DWORD), ("SegFs", wintypes.DWORD),
        ("SegEs", wintypes.DWORD), ("SegDs", wintypes.DWORD),
        ("Edi", wintypes.DWORD), ("Esi", wintypes.DWORD),
        ("Ebx", wintypes.DWORD), ("Edx", wintypes.DWORD),
        ("Ecx", wintypes.DWORD), ("Eax", wintypes.DWORD),
        ("Ebp", wintypes.DWORD), ("Eip", wintypes.DWORD),
        ("SegCs", wintypes.DWORD), ("EFlags", wintypes.DWORD),
        ("Esp", wintypes.DWORD), ("SegSs", wintypes.DWORD),
        ("ExtendedRegisters", wintypes.BYTE * 512),
    ]


class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD), ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG), ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
    ]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD), ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD), ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD), ("modBaseAddr", ctypes.POINTER(wintypes.BYTE)),
        ("modBaseSize", wintypes.DWORD), ("hModule", wintypes.HMODULE),
        ("szModule", wintypes.WCHAR * 256), ("szExePath", wintypes.WCHAR * 260),
    ]


# Correct signatures matter on a 64-bit Python host.  Target contexts are x86
# WOW64_CONTEXTs, but process and thread handles remain native-size handles.
K.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
K.OpenProcess.restype = wintypes.HANDLE
K.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
K.OpenThread.restype = wintypes.HANDLE
K.CloseHandle.argtypes = [wintypes.HANDLE]
K.CloseHandle.restype = wintypes.BOOL
K.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t]
K.VirtualQueryEx.restype = ctypes.c_size_t
K.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
K.ReadProcessMemory.restype = wintypes.BOOL
K.WriteProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
K.WriteProcessMemory.restype = wintypes.BOOL
K.VirtualAllocEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
K.VirtualAllocEx.restype = ctypes.c_void_p
K.VirtualFreeEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD]
K.VirtualFreeEx.restype = wintypes.BOOL
K.CreateRemoteThread.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
K.CreateRemoteThread.restype = wintypes.HANDLE
K.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
K.WaitForSingleObject.restype = wintypes.DWORD
K.GetExitCodeThread.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
K.GetExitCodeThread.restype = wintypes.BOOL
K.SuspendThread.argtypes = [wintypes.HANDLE]
K.SuspendThread.restype = wintypes.DWORD
K.ResumeThread.argtypes = [wintypes.HANDLE]
K.ResumeThread.restype = wintypes.DWORD
K.Wow64GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.POINTER(WOW64_CONTEXT)]
K.Wow64GetThreadContext.restype = wintypes.BOOL
K.Wow64SetThreadContext.argtypes = [wintypes.HANDLE, ctypes.POINTER(WOW64_CONTEXT)]
K.Wow64SetThreadContext.restype = wintypes.BOOL
K.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
K.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
K.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
K.Thread32First.restype = wintypes.BOOL
K.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
K.Thread32Next.restype = wintypes.BOOL
K.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
K.Module32FirstW.restype = wintypes.BOOL
K.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
K.Module32NextW.restype = wintypes.BOOL
K.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
K.GetModuleHandleW.restype = wintypes.HMODULE
K.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
K.GetProcAddress.restype = ctypes.c_void_p
U = ctypes.WinDLL("user32", use_last_error=True)
U.EnumWindows.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
U.EnumWindows.restype = wintypes.BOOL
U.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
U.GetWindowThreadProcessId.restype = wintypes.DWORD
U.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
U.GetClassNameW.restype = ctypes.c_int


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def last_error() -> int:
    return ctypes.get_last_error()


def close(h) -> None:
    if h:
        try:
            K.CloseHandle(h)
        except Exception:
            pass


def stage_base(hproc) -> tuple[int, int, int] | None:
    """Find the anonymous unpacked executable stage by exact size."""
    mbi = MBI()
    addr = 0
    # 32-bit target user VA is below 2/4 GiB.  The caller is 64-bit, so keep
    # the scan bounded and monotonic while accepting high WOW64 allocations.
    while addr < 0xFFFFFFFF:
        n = K.VirtualQueryEx(hproc, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not n:
            break
        base = int(mbi.BaseAddress or 0)
        size = int(mbi.RegionSize or 0)
        protect = int(mbi.Protect or 0) & 0xFF
        if int(mbi.State) == MEM_COMMIT and size == STAGE_SIZE and protect in (0x10, 0x20, 0x40, 0x80):
            return base, size, protect
        nxt = base + size
        if nxt <= addr:
            break
        addr = nxt
    return None


def enumerate_threads(pid: int) -> list[int]:
    snap = K.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if not snap or int(snap) == -1:
        return []
    out: list[int] = []
    try:
        ent = THREADENTRY32(); ent.dwSize = ctypes.sizeof(ent)
        if not K.Thread32First(snap, ctypes.byref(ent)):
            return out
        while True:
            if int(ent.th32OwnerProcessID) == pid:
                out.append(int(ent.th32ThreadID))
            if not K.Thread32Next(snap, ctypes.byref(ent)):
                break
    finally:
        close(snap)
    return out


def gui_threads(pid: int) -> set[int]:
    """Return threads owning the app's top-level forms (best-effort)."""
    found: set[int] = set()
    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def cb(hwnd, _lparam):
        p = wintypes.DWORD(); U.GetWindowThreadProcessId(hwnd, ctypes.byref(p))
        if int(p.value) != pid: return True
        buf = ctypes.create_unicode_buffer(128); U.GetClassNameW(hwnd, buf, 128)
        if str(buf.value) in {"TFormLogin", "TFormRegist", "TForm1", "TApplication"}:
            tid = int(U.GetWindowThreadProcessId(hwnd, ctypes.byref(p)))
            if tid: found.add(tid)
        return True
    U.EnumWindows(cb, 0)
    return found


def open_thread(tid: int):
    rights = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION
    return K.OpenThread(rights, False, tid)


def set_hw_for_thread(
    hth, addrs: list[int], clear: bool = False, access: str = "execute"
) -> dict:
    """Set up to four local execute or one-byte write slots without a debugger."""
    tid_info = {"set": False}
    if not hth:
        tid_info["error"] = last_error(); return tid_info
    prev = K.SuspendThread(hth)
    if prev == 0xFFFFFFFF:
        tid_info["error"] = last_error(); return tid_info
    try:
        c = WOW64_CONTEXT(); c.ContextFlags = WOW64_CONTEXT_DEBUG_REGISTERS
        if not K.Wow64GetThreadContext(hth, ctypes.byref(c)):
            tid_info["error"] = last_error(); return tid_info
        old = {"dr0": int(c.Dr0), "dr1": int(c.Dr1), "dr2": int(c.Dr2), "dr3": int(c.Dr3), "dr6": int(c.Dr6), "dr7": int(c.Dr7)}
        c.Dr0 = (addrs[0] if len(addrs) > 0 else 0) & 0xFFFFFFFF
        c.Dr1 = (addrs[1] if len(addrs) > 1 else 0) & 0xFFFFFFFF
        c.Dr2 = (addrs[2] if len(addrs) > 2 else 0) & 0xFFFFFFFF
        c.Dr3 = (addrs[3] if len(addrs) > 3 else 0) & 0xFFFFFFFF
        c.Dr6 = 0
        if access not in {"execute", "write"}:
            tid_info["error"] = f"unsupported hardware access mode: {access}"
            return tid_info
        control_mask = sum(0xF << (16 + 4 * i) for i in range(4))
        dr7 = int(c.Dr7) & ~0xFF & ~control_mask
        if not clear:
            dr7 |= sum(1 << (2 * i) for i in range(len(addrs)))
            if access == "write":
                dr7 |= sum(0x1 << (16 + 4 * i) for i in range(len(addrs)))
        c.Dr7 = dr7
        if not K.Wow64SetThreadContext(hth, ctypes.byref(c)):
            tid_info.update({"error": last_error(), "old": old}); return tid_info
        tid_info.update({"set": True, "old": old, "access": access, "dr": [hex(int(c.Dr0)), hex(int(c.Dr1)), hex(int(c.Dr2)), hex(int(c.Dr3))], "dr7": hex(int(c.Dr7))})
        return tid_info
    finally:
        K.ResumeThread(hth)


def remote_read(hproc, addr: int, size: int) -> bytes:
    buf = (ctypes.c_ubyte * size)(); got = ctypes.c_size_t()
    if not K.ReadProcessMemory(hproc, ctypes.c_void_p(addr), buf, size, ctypes.byref(got)):
        return b""
    return bytes(buf[:int(got.value)])


def remote_write(hproc, addr: int, data: bytes) -> bool:
    buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data); wrote = ctypes.c_size_t()
    return bool(K.WriteProcessMemory(hproc, ctypes.c_void_p(addr), buf, len(data), ctypes.byref(wrote))) and int(wrote.value) == len(data)


def local_file_export(path: Path, wanted: str) -> int:
    """Return an export RVA from a PE file (handles forwarded exports)."""
    b = path.read_bytes(); pe = struct.unpack_from("<I", b, 0x3C)[0]
    if b[pe:pe + 4] != b"PE\0\0": raise ValueError(f"not PE: {path}")
    nsec = struct.unpack_from("<H", b, pe + 6)[0]
    optsz = struct.unpack_from("<H", b, pe + 20)[0]; opt = pe + 24
    magic = struct.unpack_from("<H", b, opt)[0]; dd = opt + (96 if magic == 0x10B else 112)
    erva, esz = struct.unpack_from("<II", b, dd)
    sec = pe + 24 + optsz; sections = []
    for i in range(nsec):
        # IMAGE_SECTION_HEADER: VirtualSize, VirtualAddress, SizeOfRawData,
        # PointerToRawData (the latter is four bytes after VirtualAddress).
        vsize, va, rawsz, rawoff = struct.unpack_from("<IIII", b, sec + i * 40 + 8)
        sections.append((va, max(vsize, rawsz, 1), rawoff))
    def off(rva):
        if rva < len(b[:opt]): return rva
        for va, sz, ro in sections:
            if va <= rva < va + sz: return ro + (rva - va)
        return rva
    eo = off(erva)
    (_characteristics, _timestamp, _major, _minor, _name_rva, _ordinal_base,
     _nfunc, nname, funcs_rva, names_rva, ords_rva) = struct.unpack_from("<IIHHIIIIIII", b, eo)
    no = off(names_rva); fo = off(funcs_rva); oo = off(ords_rva)
    wanted_b = wanted.encode("ascii")
    for i in range(nname):
        nr = struct.unpack_from("<I", b, no + i * 4)[0]; n = b[off(nr):].split(b"\0", 1)[0]
        if n == wanted_b:
            ordidx = struct.unpack_from("<H", b, oo + i * 2)[0]
            return struct.unpack_from("<I", b, fo + ordidx * 4)[0]
    raise KeyError(wanted)


def remote_module_base(pid: int, wanted: str) -> int | None:
    snap = K.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if not snap or int(snap) == -1: return None
    try:
        m = MODULEENTRY32W(); m.dwSize = ctypes.sizeof(m)
        candidates: list[int] = []
        if not K.Module32FirstW(snap, ctypes.byref(m)): return None
        while True:
            if str(m.szModule).lower() == wanted.lower():
                base = int(ctypes.cast(m.modBaseAddr, ctypes.c_void_p).value or 0)
                # A 64-bit controller sees both the native and WOW64 module
                # lists.  The remote x86 thread can call only the low-address
                # image; choosing the first entry can silently pick 0x7ff... .
                if base <= 0xFFFFFFFF:
                    candidates.append(base)
            if not K.Module32NextW(snap, ctypes.byref(m)): break
        if candidates:
            return min(candidates)
    finally: close(snap)
    return None


def x86_system_dll(name: str) -> Path:
    return Path(os.environ.get("WINDIR", r"C:\Windows")) / "SysWOW64" / name


def resolve_x86_export(pid: int, name: str) -> int:
    """Resolve an x86 system export RVA plus the target's module base."""
    module = "kernel32.dll"
    # Most current Windows builds forward this to kernelbase.  Follow one
    # forwarder hop, which is enough for Add/RemoveVectoredExceptionHandler.
    rva = local_file_export(x86_system_dll(module), name)
    blob = x86_system_dll(module).read_bytes(); pe = struct.unpack_from("<I", blob, 0x3C)[0]; nsec = struct.unpack_from("<H", blob, pe + 6)[0]; optsz = struct.unpack_from("<H", blob, pe + 20)[0]; opt = pe + 24; magic = struct.unpack_from("<H", blob, opt)[0]; dd = opt + (96 if magic == 0x10B else 112); erva, esz = struct.unpack_from("<II", blob, dd); sec = pe + 24 + optsz; sections=[]
    for i in range(nsec):
        vsize, va, rawsz, rawoff = struct.unpack_from("<IIII", blob, sec + i * 40 + 8); sections.append((va, max(vsize, rawsz, 1), rawoff))
    def off(r):
        for va, sz, ro in sections:
            if va <= r < va + sz: return ro + r - va
        return r
    if erva <= rva < erva + esz:
        fwd = blob[off(rva):].split(b"\0",1)[0].decode("ascii", "replace")
        mod, fn = fwd.rsplit(".", 1); mod = mod if mod.lower().endswith(".dll") else mod + ".dll"
        base = remote_module_base(pid, mod)
        if not base: raise RuntimeError(f"remote forwarded module missing: {mod}")
        return base + local_file_export(x86_system_dll(mod), fn)
    base = remote_module_base(pid, module)
    if not base: raise RuntimeError("remote kernel32.dll not found")
    return base + rva


def mov_abs_reg(addr: int, reg: int) -> bytes:
    # 89 /r with modrm mod=00 r/m=101 -> absolute disp32.
    return b"\x89" + bytes([0x05 | ((reg & 7) << 3)]) + struct.pack("<I", addr & 0xFFFFFFFF)


def build_veh(
    log_addr: int,
    capture_stack0: bool = False,
    advance_eip: int = 0,
    capture_vm_registers: bool = False,
    capture_vm_state: bool = False,
) -> tuple[bytes, dict[str, int]]:
    """Return (handler bytes, log field map).  The function uses pushad.

    Log layout (DWORDs): seq, exception_code, tid, eip, eax, ebx, ecx, edx,
    esp, eflags, dr6, dr7, context_ptr, and optionally stack0.  The optional
    read is limited to the first DWORD at the trapped thread's CONTEXT.Esp and
    is used only by entry-point observers.  When advance_eip is non-zero, the
    trapped CONTEXT.Eip is advanced by that many bytes after the original EIP
    has been logged.  seq is incremented last.
    """
    if not 0 <= advance_eip <= 0x7F:
        raise ValueError("advance_eip must fit an unsigned imm8")
    b = bytearray(); emit = b.extend
    # On entry the OS has pushed one EXCEPTION_POINTERS* argument.  pushad
    # adds 32 bytes, so the argument is at [esp+36] (not [esp+24], which is the
    # saved ECX register).  x86 CONTEXT offsets are: Eax=b0, Ebx=a4,
    # Ecx=ac, Edx=a8, Eip=b8, EFlags=c0, Esp=c4, Dr6=14, Dr7=18.
    emit(b"\x60")                         # pushad
    emit(b"\x8b\x44\x24\x24")           # mov eax,[esp+36]
    emit(b"\x8b\x08")                     # mov ecx,[eax] EXCEPTION_RECORD*
    emit(b"\x8b\x11")                     # mov edx,[ecx] ExceptionCode
    emit(b"\x81\xfa" + struct.pack("<I", EXCEPTION_SINGLE_STEP))
    jne_pos = len(b); emit(b"\x0f\x85\x00\x00\x00\x00")
    # ecx = ContextRecord; preserve the pointer in log[12].
    emit(b"\x8b\x48\x04")                 # mov ecx,[eax+4]
    # Preserve Enigma's own single-step exceptions: only the four enabled
    # hardware slots owned by this observer are accepted as hits.
    emit(b"\xf7\x41\x14\x0f\x00\x00\x00") # test dword [ecx+Dr6],0xf
    no_dr_pos = len(b); emit(b"\x0f\x84\x00\x00\x00\x00")
    emit(b"\x89\x15" + struct.pack("<I", (log_addr + 4) & 0xFFFFFFFF))
    emit(mov_abs_reg(log_addr + 12 * 4, 1))  # mov [log+48],ecx
    # Capture register state into log indexes 3..11.
    for idx, off in [(3,0xB8), (4,0xB0), (5,0xA4), (6,0xAC), (7,0xA8), (8,0xC4), (9,0xC0), (10,0x14), (11,0x18)]:
        emit(b"\x8b\x91" + struct.pack("<I", off))
        emit(mov_abs_reg(log_addr + idx * 4, 2))
    fields = {"seq":0,"code":1,"tid":2,"eip":3,"eax":4,"ebx":5,"ecx":6,"edx":7,"esp":8,"eflags":9,"dr6":10,"dr7":11,"context":12}
    if capture_stack0:
        emit(b"\x8b\x91\xc4\x00\x00\x00")  # mov edx,[ecx+Esp]
        emit(b"\x8b\x12")                       # mov edx,[edx]
        emit(mov_abs_reg(log_addr + 13 * 4, 2))
        fields["stack0"] = 13
    if capture_vm_registers or capture_vm_state:
        # Capture VM cursor/stack candidates at exception time, not later
        # from a CONTEXT pointer whose lifetime ends when this handler returns.
        for name, off in (("esi", 0xA0), ("edi", 0x9C), ("ebp", 0xB4)):
            index = max(fields.values()) + 1
            emit(b"\x8b\x91" + struct.pack("<I", off))
            emit(mov_abs_reg(log_addr + index * 4, 2))
            fields[name] = index
    if capture_vm_state:
        # Both snapshots are taken before the interrupted instruction resumes.
        # Bound each source range to this thread's committed stack using the
        # x86 TEB StackLimit/StackBase, so arbitrary VM pointers are not read.
        for name, context_offset, destination_offset in (
            ("esp_snapshot_valid", 0xC4, 0x100),
            ("ebp_snapshot_valid", 0xB4, 0x200),
        ):
            index = max(fields.values()) + 1
            fields[name] = index
            valid_addr = log_addr + index * 4
            emit(b"\xc7\x05" + struct.pack("<I", valid_addr) + b"\x00\x00\x00\x00")
            emit(b"\x51")  # preserve CONTEXT pointer in ECX
            emit(b"\x8b\xb1" + struct.pack("<I", context_offset))
            emit(b"\x64\xa1\x08\x00\x00\x00")  # TEB.StackLimit
            emit(b"\x39\xc6")  # cmp esi,eax
            below = len(b); emit(b"\x0f\x82\x00\x00\x00\x00")
            emit(b"\x89\xf0\x05\x00\x01\x00\x00")  # eax=source+256
            overflow = len(b); emit(b"\x0f\x82\x00\x00\x00\x00")
            emit(b"\x64\x8b\x15\x04\x00\x00\x00")  # TEB.StackBase
            emit(b"\x39\xd0")  # cmp eax,edx
            above = len(b); emit(b"\x0f\x87\x00\x00\x00\x00")
            emit(b"\xbf" + struct.pack("<I", log_addr + destination_offset))
            emit(b"\xb9\x40\x00\x00\x00\xfc\xf3\xa5")  # cld; rep movsd
            emit(b"\xc7\x05" + struct.pack("<I", valid_addr) + b"\x01\x00\x00\x00")
            skip = len(b)
            emit(b"\x59")  # restore CONTEXT pointer
            for branch in (below, overflow, above):
                struct.pack_into("<i", b, branch + 2, skip - (branch + 6))
    # TEB.ClientId.UniqueThread at fs:[0x24].
    emit(b"\x64\xa1\x24\x00\x00\x00")
    emit(mov_abs_reg(log_addr + 2 * 4, 0))
    # Disable all local execute/data slots for this thread before retrying the
    # trapped instruction; the external poller can re-arm the thread later.
    emit(b"\x8b\x51\x18")                    # mov edx,[ecx+Dr7]
    emit(b"\x81\xe2\x00\xff\xff\xff")       # and edx,ffffff00
    emit(b"\x89\x51\x18")                    # mov [ecx+Dr7],edx
    if advance_eip:
        # add dword ptr [ecx+CONTEXT.Eip], imm8.  This is used by a narrow
        # execute-breakpoint experiment to skip one already-identified writer
        # without patching its code bytes.
        emit(b"\x83\x81\xb8\x00\x00\x00" + bytes([advance_eip]))
    # PUSHAD stores registers in reverse order: [esp+0x1c] is saved EAX.
    # The exception callback's return value is restored from that slot after
    # POPAD.
    emit(b"\xc7\x44\x24\x1c\xff\xff\xff\xff")
    # lock inc [log.seq]; this is last so readers see a complete record.
    emit(b"\xf0\xff\x05" + struct.pack("<I", log_addr & 0xFFFFFFFF))
    jmp_done = len(b); emit(b"\xe9\x00\x00\x00\x00")
    # Not-hit: return EXCEPTION_CONTINUE_SEARCH (0).
    nonhit = len(b); emit(b"\xc7\x44\x24\x1c\x00\x00\x00\x00")
    done = len(b); emit(b"\x61\xc2\x04\x00")  # popad; ret 4 (CALLBACK/stdcall)
    struct.pack_into("<i", b, jne_pos + 2, nonhit - (jne_pos + 6))
    struct.pack_into("<i", b, no_dr_pos + 2, nonhit - (no_dr_pos + 6))
    struct.pack_into("<i", b, jmp_done + 1, done - (jmp_done + 5))
    return bytes(b), fields


def build_register_stub(code_addr: int, handler_addr: int, addveh: int) -> bytes:
    # stdcall AddVectoredExceptionHandler(1, handler), then return its pointer
    # as the remote thread exit code (useful as registration evidence).
    return b"\x68" + struct.pack("<I", handler_addr & 0xFFFFFFFF) + b"\x6a\x01\xb8" + struct.pack("<I", addveh & 0xFFFFFFFF) + b"\xff\xd0\xc2\x04\x00"


def inject_veh(
    hproc,
    pid: int,
    capture_stack0: bool = False,
    advance_eip: int = 0,
    capture_vm_registers: bool = False,
    capture_vm_state: bool = False,
) -> dict:
    log_size = 0x300 if capture_vm_state else 0x100
    code_size = 0x1000
    log_addr = int(K.VirtualAllocEx(hproc, None, log_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) or 0)
    code_addr = int(K.VirtualAllocEx(hproc, None, code_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) or 0)
    if not log_addr or not code_addr:
        raise ctypes.WinError(last_error())
    handler, fields = build_veh(
        log_addr,
        capture_stack0=capture_stack0,
        advance_eip=advance_eip,
        capture_vm_registers=capture_vm_registers,
        capture_vm_state=capture_vm_state,
    )
    addveh = resolve_x86_export(pid, "AddVectoredExceptionHandler")
    stub = build_register_stub(code_addr, code_addr, addveh)
    body = handler + b"\x90" * ((0x100 - (len(handler) % 0x100)) % 0x100) + stub
    if not remote_write(hproc, code_addr, body) or not remote_write(hproc, log_addr, b"\0" * log_size):
        raise ctypes.WinError(last_error())
    thid = wintypes.DWORD()
    hrt = K.CreateRemoteThread(hproc, None, 0, ctypes.c_void_p(code_addr + len(handler) + ((0x100 - (len(handler) % 0x100)) % 0x100)), None, 0, ctypes.byref(thid))
    if not hrt:
        raise ctypes.WinError(last_error())
    try:
        wait = K.WaitForSingleObject(hrt, 5000); exitc = wintypes.DWORD(); K.GetExitCodeThread(hrt, ctypes.byref(exitc))
    finally: close(hrt)
    return {"code": code_addr, "log": log_addr, "log_size": log_size, "handler": code_addr, "register_stub": code_addr + len(handler) + ((0x100 - (len(handler) % 0x100)) % 0x100), "addveh": addveh, "remote_thread": int(thid.value), "wait": int(wait), "exit_code": int(exitc.value), "fields": fields}


def parse_log(raw: bytes, fields: dict) -> dict | None:
    count = max(fields.values(), default=-1) + 1
    if count <= 0 or len(raw) < count * 4: return None
    vals = struct.unpack_from(f"<{count}I", raw, 0)
    return {name: int(vals[idx]) for name, idx in fields.items() if idx < len(vals)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", type=Path, default=TARGET_DEFAULT)
    ap.add_argument("--helper", type=Path, default=HELPER_DEFAULT)
    ap.add_argument("--out", type=Path, default=OUT_DEFAULT)
    ap.add_argument("--seconds", type=float, default=38.0)
    ap.add_argument("--poll-ms", type=int, default=30)
    ap.add_argument("--no-helper", action="store_true")
    ap.add_argument("--no-hw", action="store_true", help="install VEH but do not set DR0-DR3 (diagnostic control)")
    ap.add_argument("--arm-delay", type=float, default=0.0, help="seconds to wait after stage/VEH before setting DR0-DR3")
    ap.add_argument("--gui-only", action="store_true", help="arm only a thread owning TFormLogin/TFormRegist/TForm1")
    ap.add_argument("--max-threads", type=int, default=0, help="limit newly armed threads (0 means all)")
    ap.add_argument("--rvas", type=str, help="comma-separated name=hexrva list")
    args = ap.parse_args(); target = args.target.resolve(); out = args.out.resolve(); out.mkdir(parents=True, exist_ok=True)
    rvas = dict(DEFAULT_RVAS)
    if args.rvas:
        rvas = {}
        for item in args.rvas.split(","):
            n, v = item.split("=", 1); rvas[n] = int(v, 0)
    stamp = str(int(time.time())); log_path = out / f"external_hwtrace_{stamp}.jsonl"; summ_path = out / f"external_hwtrace_{stamp}.summary.json"; ui_path = out / f"external_hwtrace_{stamp}.ui.jsonl"
    rec = {"schema":"chessshark.external-hwtrace.v1", "target":str(target), "target_sha256":sha256(target), "started_ms":int(time.time()*1000), "stage":None, "breakpoints":{}, "veh":None, "threads":{}, "hits":[], "artifacts":{"log":str(log_path),"summary":str(summ_path),"ui":str(ui_path)}}
    if not target.exists(): raise SystemExit(f"missing target: {target}")
    target_proc = None; hproc = None; handles: dict[int, object] = {}; helper = None; veh = None; last_seq = 0; rows: list[dict] = []
    try:
        target_proc = subprocess.Popen([str(target)], cwd=str(target.parent), creationflags=subprocess.CREATE_NEW_CONSOLE)
        deadline = time.monotonic() + min(args.seconds, 20.0); stage = None
        while time.monotonic() < deadline and target_proc.poll() is None:
            hproc = K.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, False, target_proc.pid)
            if hproc:
                stage = stage_base(hproc)
                if stage: break
                close(hproc); hproc = None
            time.sleep(0.05)
        if not hproc or not stage: raise RuntimeError("normal start did not expose 0x793000 stage")
        base, size, prot = stage; rec["stage"] = {"base":hex(base),"size":hex(size),"protect":hex(prot),"detected_ms":int(time.time()*1000)}
        addresses = {name: base + int(rva) for name, rva in rvas.items()}; rec["breakpoints"] = {n:{"rva":hex(v),"address":hex(addresses[n])} for n,v in rvas.items()}
        veh = inject_veh(hproc, target_proc.pid); rec["veh"] = {k:(hex(v) if k in {"code","log","handler","register_stub","addveh"} else v) for k,v in veh.items() if k != "fields"}; rec["veh"]["fields"] = veh["fields"]
        addrs = [] if args.no_hw else list(addresses.values())[:4]
        # Set the initial and any newly created target threads.  Opening a
        # running thread is sufficient because SuspendThread brackets context.
        if not args.no_helper and args.helper.exists():
            helper = subprocess.Popen([sys.executable, str(args.helper), "--pid", str(target_proc.pid), "--target-exe", str(target), "--seconds", str(max(args.seconds-2, 8)), "--poll-ms", "50", "--update-action", "defer", "--registration-action", "copy", "--login-action", "probe", "--messagebox-action", "ok", "--registration-wm-command", "--log", str(ui_path)], cwd=str(target.parent))
        if addrs and args.arm_delay > 0:
            time.sleep(args.arm_delay)
        end = time.monotonic() + args.seconds; installed: set[int] = set()
        while time.monotonic() < end and target_proc.poll() is None:
            tids = enumerate_threads(target_proc.pid)
            if args.gui_only:
                gt = gui_threads(target_proc.pid)
                tids = [tid for tid in tids if tid in gt]
            if args.max_threads > 0:
                tids = tids[:args.max_threads]
            for tid in tids:
                if tid in installed: continue
                hth = open_thread(tid)
                if hth:
                    res = set_hw_for_thread(hth, addrs); rec["threads"][str(tid)] = res; handles[tid] = hth
                    if res.get("set"): installed.add(tid)
                    else: close(hth)
            raw = remote_read(hproc, int(veh["log"]), 0x100); row = parse_log(raw, veh["fields"])
            if row and row.get("seq",0) != last_seq:
                last_seq = row["seq"]; row.update({"ts_ms":int(time.time()*1000),"seq":last_seq}); rows.append(row); rec["hits"].append(row)
                # Read the saved stack and a short code window from the
                # controller side.  Keeping this outside the VEH avoids
                # dereferencing an untrusted stack pointer in the target.
                stack_raw = remote_read(hproc, int(row.get("esp", 0)), 32)
                if len(stack_raw) == 32:
                    row["stack_external"] = list(struct.unpack("<8I", stack_raw))
                code_raw = remote_read(hproc, int(row.get("eip", 0)), 16)
                if code_raw:
                    row["code_window"] = code_raw.hex()
            time.sleep(max(args.poll_ms, 5)/1000.0)
    except Exception as e:
        rec["error"] = {"type":type(e).__name__,"message":str(e),"winerr":last_error()}
    finally:
        # Clear DR enables before returning, preserving only transient state.
        for tid, hth in list(handles.items()):
            try: set_hw_for_thread(hth, [], clear=True)
            except Exception: pass
            close(hth)
        if helper is not None:
            try: helper.wait(timeout=5)
            except subprocess.TimeoutExpired:
                helper.kill()
        if target_proc is not None and target_proc.poll() is None:
            try: target_proc.terminate(); target_proc.wait(timeout=5)
            except Exception:
                try: target_proc.kill()
                except Exception: pass
        if hproc: close(hproc)
        rec["finished_ms"] = int(time.time()*1000); rec["helper_returncode"] = helper.returncode if helper else None; rec["rows"] = len(rows); rec["target_returncode"] = target_proc.returncode if target_proc else None
        with log_path.open("w", encoding="utf-8") as f:
            for row in rows: f.write(json.dumps(row, ensure_ascii=False) + "\n")
        summ_path.write_text(json.dumps(rec, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(rec, ensure_ascii=False, indent=2)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
