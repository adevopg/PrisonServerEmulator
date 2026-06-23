import ctypes as C, ctypes.wintypes as W, subprocess, time, sys
k32=C.windll.kernel32
k32.VirtualAllocEx.restype=C.c_void_p
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
    old=W.DWORD(0); k32.VirtualProtectEx(h,C.c_void_p(addr),len(b),0x40,C.byref(old))
    buf=C.create_string_buffer(b,len(b)); wr=C.c_size_t()
    k32.WriteProcessMemory(h,C.c_void_p(addr),buf,len(b),C.byref(wr))
    k32.VirtualProtectEx(h,C.c_void_p(addr),len(b),old,C.byref(old)); k32.FlushInstructionCache(h,C.c_void_p(addr),len(b))
def wr32(addr,v):
    b=C.create_string_buffer(v.to_bytes(4,'little'),4); w=C.c_size_t()
    k32.WriteProcessMemory(h,C.c_void_p(addr),b,4,C.byref(w))
def rd32(addr):
    b=(C.c_char*4)(); g=C.c_size_t(); k32.ReadProcessMemory(h,C.c_void_p(addr),b,4,C.byref(g)); return int.from_bytes(b.raw,'little')
# patches: force net 0x13d4 -> 0x40c50c -> fire 0x482
patch(0x40b7be, bytes([0xe9,0x49,0x0d,0x00,0x00,0x90]))
patch(0x40c513, bytes([0x90,0x90]))
# forge account struct (0x1000 zeroed) and keep [0x5be62c] pointing at it
mem=k32.VirtualAllocEx(h,None,0x1000,0x3000,0x04)
print("forged account @%08x patched, holding [0x5be62c]"%mem); sys.stdout.flush()
dur=float(sys.argv[1]) if len(sys.argv)>1 else 14
t0=time.time()
while time.time()-t0<dur:
    if rd32(0x5be62c)==0: wr32(0x5be62c, mem)
    time.sleep(0.03)
print("done; screen=%x loginPhase=%x"%(rd32(0x5bd448),rd32(0x5eda4c)))
