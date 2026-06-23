import ctypes as C, ctypes.wintypes as W, subprocess, time, sys
k32=C.windll.kernel32
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
def wr(addr,val,n=4):
    b=C.create_string_buffer(val.to_bytes(n,'little'),n); w=C.c_size_t()
    k32.WriteProcessMemory(h,C.c_void_p(addr),b,n,C.byref(w))
def rd(addr):
    b=(C.c_char*4)(); g=C.c_size_t(); k32.ReadProcessMemory(h,C.c_void_p(addr),b,4,C.byref(g)); return int.from_bytes(b.raw,'little')
dur=float(sys.argv[1]) if len(sys.argv)>1 else 12.0
t0=time.time()
print("forcing loginPhase=2, screen=0xc on pid",pid); sys.stdout.flush()
while time.time()-t0<dur:
    wr(0x5eda4c,2)      # loginPhase=2
    wr(0x5bd448,0xc)    # screen = server-select
    time.sleep(0.02)
print("final screen=%x loginPhase=%x"%(rd(0x5bd448),rd(0x5eda4c)))
