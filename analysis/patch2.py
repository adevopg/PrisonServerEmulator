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
h=k32.OpenProcess(0x08|0x10|0x20|0x400,False,pid)
def patch(addr,b):
    old=W.DWORD(0)
    k32.VirtualProtectEx(h,C.c_void_p(addr),len(b),0x40,C.byref(old))
    buf=C.create_string_buffer(b,len(b)); wr=C.c_size_t()
    ok=k32.WriteProcessMemory(h,C.c_void_p(addr),buf,len(b),C.byref(wr))
    k32.VirtualProtectEx(h,C.c_void_p(addr),len(b),old,C.byref(old))
    k32.FlushInstructionCache(h,C.c_void_p(addr),len(b))
    rb=(C.c_char*len(b))(); g=C.c_size_t(); k32.ReadProcessMemory(h,C.c_void_p(addr),rb,len(b),C.byref(g))
    print("patch %08x ok=%d -> %s"%(addr,ok,' '.join('%02x'%x for x in rb.raw)))
# (1) force count==0 branch: je 0x40c50c -> jmp 0x40c50c
patch(0x40b7be, bytes([0xe9,0x49,0x0d,0x00,0x00,0x90]))
# (2) always fire 0x482: NOP the je at 0x40c513
patch(0x40c513, bytes([0x90,0x90]))
print("patched")
