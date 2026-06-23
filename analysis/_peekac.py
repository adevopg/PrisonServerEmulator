import ctypes as C, subprocess, time, sys
k32=C.windll.kernel32
def pid_of(n):
    out=subprocess.check_output(["tasklist","/fi","imagename eq %s"%n,"/fo","csv","/nh"],text=True)
    for l in out.splitlines():
        if n.lower() in l.lower(): return int(l.split(",")[1].strip('"'))
pid=None
for _ in range(60):
    pid=pid_of("Carcelclient.exe")
    if pid: break
    time.sleep(0.1)
if not pid: print("noclient"); sys.exit()
h=k32.OpenProcess(0x10,False,pid)
def rdd(a):
    b=(C.c_char*4)(); g=C.c_size_t()
    return int.from_bytes(b.raw,"little") if k32.ReadProcessMemory(h,C.c_void_p(a),b,4,C.byref(g)) else -1
for t in range(8):
    time.sleep(0.5)
    print("t+%.1f AutoChar[5eda38]=%d selGuard[5ec5fe]=%d acGuard[5f247d]=%d screen=0x%x"%(
        t*0.5, rdd(0x5eda38), rdd(0x5ec5fe)&0xff, rdd(0x5f247d)&0xff, rdd(0x5bd448)))
