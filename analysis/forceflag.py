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
h=k32.OpenProcess(0x10|0x20,False,pid)   # VM_READ|VM_WRITE
print("forcing [0x5be628]=0 on pid",pid); sys.stdout.flush()
zero=C.create_string_buffer(b"\x00",1); wr=C.c_size_t()
dur=float(sys.argv[1]) if len(sys.argv)>1 else 14.0
t0=time.time(); n=0
while time.time()-t0 < dur:
    k32.WriteProcessMemory(h,C.c_void_p(0x5be628),zero,1,C.byref(wr)); n+=1
    time.sleep(0.01)
print("done, %d writes"%n)
