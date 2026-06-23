import ctypes as C, ctypes.wintypes as W, subprocess, time, sys
k32=C.windll.kernel32
def pid_of(n):
    out=subprocess.check_output(['tasklist','/fi','imagename eq %s'%n,'/fo','csv','/nh'],text=True)
    for l in out.splitlines():
        if n.lower() in l.lower(): return int(l.split(',')[1].strip('"'))
pid=None
for _ in range(60):
    pid=pid_of("Carcelclient.exe")
    if pid: break
    time.sleep(0.2)
if not pid: print("noclient"); sys.exit()
# PROCESS_VM_OPERATION|VM_READ|VM_WRITE|QUERY
h=k32.OpenProcess(0x08|0x10|0x20|0x400,False,pid)
if not h: print("OpenProcess failed",k32.GetLastError()); sys.exit()
addr=0x40bdf8; n=6
def rd(a,nn):
    b=(C.c_char*nn)(); g=C.c_size_t(); k32.ReadProcessMemory(h,C.c_void_p(a),b,nn,C.byref(g)); return b.raw[:g.value]
print("before:",' '.join('%02x'%x for x in rd(addr,n)))
old=W.DWORD(0)
vp=k32.VirtualProtectEx(h,C.c_void_p(addr),n,0x40,C.byref(old))  # PAGE_EXECUTE_READWRITE
nop=C.create_string_buffer(b"\x90"*n,n); wr=C.c_size_t()
ok=k32.WriteProcessMemory(h,C.c_void_p(addr),nop,n,C.byref(wr))
le=k32.GetLastError()
k32.VirtualProtectEx(h,C.c_void_p(addr),n,old,C.byref(old))
k32.FlushInstructionCache(h,C.c_void_p(addr),n)
print("after :",' '.join('%02x'%x for x in rd(addr,n)),"vp=",vp,"ok=",ok,"err=",le)
