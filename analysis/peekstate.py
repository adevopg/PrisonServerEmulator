import ctypes as C, ctypes.wintypes as W, subprocess, sys
k32=C.windll.kernel32
def pid_of(n):
    out=subprocess.check_output(['tasklist','/fi','imagename eq %s'%n,'/fo','csv','/nh'],text=True)
    for l in out.splitlines():
        if n.lower() in l.lower(): return int(l.split(',')[1].strip('"'))
pid=pid_of("Carcelclient.exe")
if not pid: print("noclient"); sys.exit()
h=k32.OpenProcess(0x10,False,pid)
def rdd(a):
    b=(C.c_char*4)(); g=C.c_size_t()
    return int.from_bytes(b.raw,'little') if k32.ReadProcessMemory(h,C.c_void_p(a),b,4,C.byref(g)) else -1
print("screen=%x loginPhase=%x acctPtr=%x updFlag=%x"%(rdd(0x5bd448),rdd(0x5eda4c),rdd(0x5be62c),rdd(0x5be628)))
