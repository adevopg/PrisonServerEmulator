# Minimal Win32 debugger (ctypes) for Carcelclient.exe (no ASLR, base 0x400000).
# Sets INT3 breakpoints at key login/accept addresses and logs hits + registers
# + key globals, so we can see what the client executes while our server drives it.
import ctypes as C, ctypes.wintypes as W, sys

k32 = C.windll.kernel32
EXE = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
CWD = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer"

DEBUG_ONLY_THIS_PROCESS=2; DEBUG_PROCESS=1; CREATE_NEW_CONSOLE=0x10
DBG_CONTINUE=0x00010002; DBG_EXCEPTION_NOT_HANDLED=0x80010001
EXCEPTION_BREAKPOINT=0x80000003; EXCEPTION_SINGLE_STEP=0x80000004
CREATE_PROCESS_DEBUG_EVENT=3; EXCEPTION_DEBUG_EVENT=1; EXIT_PROCESS_DEBUG_EVENT=5
LOAD_DLL_DEBUG_EVENT=6
CONTEXT_CONTROL=0x10001; CONTEXT_FULL=0x10007

# Breakpoints: addr -> label
BPS = {
 0x40a59e: "net0x1388 ACCOUNT-DATA recv",
 0x40b7bb: "net0x13d4 SERVERLIST recv",
 0x40c476: "ACCEPT-check [0x5be628]?",
 0x40c487: "*** FIRE LOGINACCEPTED(0x482) ***",
 0x40c4a7: "accept->ELSE 'update complete'",
 0x409958: "SET flag [0x5be628]=1",
 0x40a9a4: "net0x1389 LOGINREJECTED recv",
 0x40a68a2: "LOGINACCEPTED ui handler",
}
GLOBALS = {0x5be628:"flag628",0x5be62b:"flag62b",0x5be62c:"acctPtr"}

class STARTUPINFO(C.Structure):
    _fields_=[("cb",W.DWORD),("lpReserved",W.LPWSTR),("lpDesktop",W.LPWSTR),
    ("lpTitle",W.LPWSTR),("dwX",W.DWORD),("dwY",W.DWORD),("dwXSize",W.DWORD),
    ("dwYSize",W.DWORD),("dwXCountChars",W.DWORD),("dwYCountChars",W.DWORD),
    ("dwFillAttribute",W.DWORD),("dwFlags",W.DWORD),("wShowWindow",W.WORD),
    ("cbReserved2",W.WORD),("lpReserved2",C.c_void_p),("hStdInput",W.HANDLE),
    ("hStdOutput",W.HANDLE),("hStdError",W.HANDLE)]
class PROCESS_INFORMATION(C.Structure):
    _fields_=[("hProcess",W.HANDLE),("hThread",W.HANDLE),("dwProcessId",W.DWORD),("dwThreadId",W.DWORD)]
class EXCEPTION_RECORD(C.Structure):
    _fields_=[("ExceptionCode",W.DWORD),("ExceptionFlags",W.DWORD),
    ("ExceptionRecord",C.c_void_p),("ExceptionAddress",C.c_void_p),
    ("NumberParameters",W.DWORD),("ExceptionInformation",C.c_void_p*15)]
class EXCEPTION_DEBUG_INFO(C.Structure):
    _fields_=[("ExceptionRecord",EXCEPTION_RECORD),("dwFirstChance",W.DWORD)]
class DEBUG_EVENT(C.Structure):
    class U(C.Union):
        _fields_=[("Exception",EXCEPTION_DEBUG_INFO),("raw",C.c_byte*160)]
    _fields_=[("dwDebugEventCode",W.DWORD),("dwProcessId",W.DWORD),
    ("dwThreadId",W.DWORD),("u",U)]

# x86 CONTEXT (partial, enough for EIP/regs)
class FLOATING_SAVE_AREA(C.Structure):
    _fields_=[("ControlWord",W.DWORD),("StatusWord",W.DWORD),("TagWord",W.DWORD),
    ("ErrorOffset",W.DWORD),("ErrorSelector",W.DWORD),("DataOffset",W.DWORD),
    ("DataSelector",W.DWORD),("RegisterArea",C.c_byte*80),("Cr0NpxState",W.DWORD)]
class CONTEXT(C.Structure):
    _fields_=[("ContextFlags",W.DWORD),("Dr0",W.DWORD),("Dr1",W.DWORD),("Dr2",W.DWORD),
    ("Dr3",W.DWORD),("Dr6",W.DWORD),("Dr7",W.DWORD),("FloatSave",FLOATING_SAVE_AREA),
    ("SegGs",W.DWORD),("SegFs",W.DWORD),("SegEs",W.DWORD),("SegDs",W.DWORD),
    ("Edi",W.DWORD),("Esi",W.DWORD),("Ebx",W.DWORD),("Edx",W.DWORD),("Ecx",W.DWORD),
    ("Eax",W.DWORD),("Ebp",W.DWORD),("Eip",W.DWORD),("SegCs",W.DWORD),
    ("EFlags",W.DWORD),("Esp",W.DWORD),("SegSs",W.DWORD),("ExtendedRegisters",C.c_byte*512)]

TH32CS_SNAPTHREAD=4
class THREADENTRY32(C.Structure):
    _fields_=[("dwSize",W.DWORD),("cntUsage",W.DWORD),("th32ThreadID",W.DWORD),
    ("th32OwnerProcessID",W.DWORD),("tpBasePri",C.c_long),("tpDeltaPri",C.c_long),("dwFlags",W.DWORD)]
def suspend_others(pid,keepTid):
    snap=k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0); susp=[]
    te=THREADENTRY32(); te.dwSize=C.sizeof(te)
    if k32.Thread32First(snap,C.byref(te)):
        while True:
            if te.th32OwnerProcessID==pid and te.th32ThreadID!=keepTid:
                h=k32.OpenThread(0x0002,False,te.th32ThreadID)  # SUSPEND_RESUME
                if h: k32.SuspendThread(h); susp.append(h)
            if not k32.Thread32Next(snap,C.byref(te)): break
    k32.CloseHandle(snap); return susp
def resume_all(susp):
    for h in susp: k32.ResumeThread(h); k32.CloseHandle(h)

def rdmem(h,addr,n):
    buf=(C.c_char*n)(); got=C.c_size_t()
    k32.ReadProcessMemory(h,C.c_void_p(addr),buf,n,C.byref(got))
    return buf.raw[:got.value]
def wrmem(h,addr,data):
    buf=C.create_string_buffer(bytes(data),len(data)); wr=C.c_size_t()
    k32.WriteProcessMemory(h,C.c_void_p(addr),buf,len(data),C.byref(wr))
    k32.FlushInstructionCache(h,C.c_void_p(addr),len(data))

def main():
    si=STARTUPINFO(); si.cb=C.sizeof(si); pi=PROCESS_INFORMATION()
    ok=k32.CreateProcessW(EXE,None,None,None,False,
        DEBUG_ONLY_THIS_PROCESS|CREATE_NEW_CONSOLE,None,CWD,C.byref(si),C.byref(pi))
    if not ok: print("CreateProcess failed",k32.GetLastError()); return
    hProc=pi.hProcess
    # Clear PEB->BeingDebugged (anti-debug bypass)
    try:
        ntdll=C.windll.ntdll
        class PBI(C.Structure):
            _fields_=[("Reserved1",C.c_void_p),("PebBaseAddress",C.c_void_p),
            ("Reserved2",C.c_void_p*2),("UniqueProcessId",C.c_void_p),("Reserved3",C.c_void_p)]
        pbi=PBI(); rl=C.c_ulong()
        ntdll.NtQueryInformationProcess(hProc,0,C.byref(pbi),C.sizeof(pbi),C.byref(rl))
        peb=C.cast(pbi.PebBaseAddress,C.c_void_p).value or 0
        if peb:
            # BeingDebugged @ +2 ; NtGlobalFlag @ +0x68
            wr=C.c_size_t(); zero=C.create_string_buffer(b"\x00",1)
            k32.WriteProcessMemory(hProc,C.c_void_p(peb+2),zero,1,C.byref(wr))
            z4=C.create_string_buffer(b"\x00\x00\x00\x00",4)
            k32.WriteProcessMemory(hProc,C.c_void_p(peb+0x68),z4,4,C.byref(wr))
            print("[dbg] PEB %08x BeingDebugged cleared"%peb)
    except Exception as e: print("[dbg] peb clear failed",e)
    orig={}   # addr->orig byte
    pending=None
    de=DEBUG_EVENT()
    import time; start=time.time()
    armed=False
    def arm():
        for a in BPS:
            ob=rdmem(hProc,a,1)
            if ob:
                orig[a]=ob[0]; wrmem(hProc,a,b"\xCC")
        print("[dbg] %d breakpoints armed"%len(orig)); sys.stdout.flush()
    while True:
        if not k32.WaitForDebugEvent(C.byref(de),2000):
            if time.time()-start>90: print("[dbg] timeout"); break
            continue
        code=de.dwDebugEventCode; cont=DBG_CONTINUE
        if code==CREATE_PROCESS_DEBUG_EVENT:
            arm(); armed=True
        elif code==EXCEPTION_DEBUG_EVENT:
            er=de.u.Exception.ExceptionRecord
            ec=er.ExceptionCode; addr=er.ExceptionAddress or 0
            if ec==EXCEPTION_BREAKPOINT and addr in orig:
                susp=suspend_others(pi.dwProcessId,de.dwThreadId)  # serialize: only this thread runs
                hT=k32.OpenThread(0x1F03FF,False,de.dwThreadId)
                ctx=CONTEXT(); ctx.ContextFlags=CONTEXT_FULL
                k32.GetThreadContext(hT,C.byref(ctx))
                gl=" ".join("%s=%08x"%(n,int.from_bytes(rdmem(hProc,g,4) or b'\0\0\0\0','little')) for g,n in GLOBALS.items())
                print("[BP] %08x %-32s EAX=%08x EBX=%08x ECX=%08x EDX=%08x | %s"%(
                    addr,BPS[addr],ctx.Eax,ctx.Ebx,ctx.Ecx,ctx.Edx,gl)); sys.stdout.flush()
                wrmem(hProc,addr,bytes([orig[addr]]))
                ctx.Eip=addr; ctx.EFlags|=0x100
                ctx.ContextFlags=CONTEXT_FULL
                k32.SetThreadContext(hT,C.byref(ctx))
                pending=(addr,susp); k32.CloseHandle(hT)
            elif ec==EXCEPTION_SINGLE_STEP and pending is not None:
                wrmem(hProc,pending[0],b"\xCC"); resume_all(pending[1]); pending=None
            elif ec in (EXCEPTION_BREAKPOINT,EXCEPTION_SINGLE_STEP):
                cont=DBG_CONTINUE   # loader/system breakpoint -> swallow
            else:
                cont=DBG_EXCEPTION_NOT_HANDLED
        elif code==EXIT_PROCESS_DEBUG_EVENT:
            ec2=W.DWORD(); k32.GetExitCodeProcess(hProc,C.byref(ec2))
            print("[dbg] process exited code=0x%x"%ec2.value); k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,cont); break
        k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,cont)
        if time.time()-start>90: print("[dbg] time limit"); break

main()
