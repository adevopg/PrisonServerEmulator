import ctypes as C, ctypes.wintypes as W, sys, time, subprocess
k32=C.windll.kernel32
def pid_of(name):
    out=subprocess.check_output(['tasklist','/fi','imagename eq %s'%name,'/fo','csv','/nh'],text=True)
    for line in out.splitlines():
        if name.lower() in line.lower(): return int(line.split(',')[1].strip('"'))
    return None
pid=None
for _ in range(40):
    pid=pid_of("Carcelclient.exe")
    if pid: break
    time.sleep(0.25)
if not pid: print("no client"); sys.exit()
h=k32.OpenProcess(0x10|0x400,False,pid)
def rd(a,n=4):
    buf=(C.c_char*n)(); got=C.c_size_t()
    ok=k32.ReadProcessMemory(h,C.c_void_p(a),buf,n,C.byref(got))
    return buf.raw[:got.value] if ok else None
def rdd(a):
    b=rd(a,4); return int.from_bytes(b,'little') if b else None
def hexd(b):
    return ' '.join('%02x'%x for x in b) if b else 'None'
# wait for connection to establish + our msgs sent
time.sleep(6)
for g in (0x5be620,0x5be62c,0x5bd448,0x5be628):
    print("global %08x = %08x"%(g, rdd(g) or 0))
conn=rdd(0x5be620)
print("\n[0x5be620] conn ptr = %08x"%(conn or 0))
if conn:
    d=rd(conn,0x80)
    for off in range(0,0x80,16):
        print("  +%02x: %s"%(off, hexd(d[off:off+16]) if d else '?'))
