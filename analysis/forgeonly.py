import ctypes as C, ctypes.wintypes as W, subprocess, time, sys
k32=C.windll.kernel32; k32.VirtualAllocEx.restype=C.c_void_p
def pid_of(n):
    out=subprocess.check_output(['tasklist','/fi','imagename eq %s'%n,'/fo','csv','/nh'],text=True)
    for l in out.splitlines():
        if n.lower() in l.lower(): return int(l.split(',')[1].strip('"'))
pid=None
for _ in range(40):
    pid=pid_of("Carcelclient.exe")
    if pid: break
    time.sleep(0.25)
if not pid: print("noclient"); sys.exit()
h=k32.OpenProcess(0x08|0x10|0x20|0x400,False,pid)
mem=k32.VirtualAllocEx(h,None,0x4000,0x3000,0x04)   # zeroed account buffer
def wr32(a,v):
    b=C.create_string_buffer(v.to_bytes(4,'little'),4); w=C.c_size_t(); k32.WriteProcessMemory(h,C.c_void_p(a),b,4,C.byref(w))
def rd32(a):
    b=(C.c_char*4)(); g=C.c_size_t(); k32.ReadProcessMemory(h,C.c_void_p(a),b,4,C.byref(g)); return int.from_bytes(b.raw,'little')
print("forging [0x5be62c]=%08x (zeroed account)"%mem); sys.stdout.flush()
dur=float(sys.argv[1]) if len(sys.argv)>1 else 16
t0=time.time()
while time.time()-t0<dur:
    if rd32(0x5be62c)==0: wr32(0x5be62c, mem)
    time.sleep(0.02)
print("done screen=%x loginPhase=%x"%(rd32(0x5bd448),rd32(0x5eda4c)))
