import ctypes as C, ctypes.wintypes as W, sys, time, subprocess, struct
k32=C.windll.kernel32
class MBI(C.Structure):
    _fields_=[("BaseAddress",C.c_void_p),("AllocationBase",C.c_void_p),("AllocationProtect",W.DWORD),
    ("RegionSize",C.c_size_t),("State",W.DWORD),("Protect",W.DWORD),("Type",W.DWORD)]
def pid_of(name):
    out=subprocess.check_output(['tasklist','/fi','imagename eq %s'%name,'/fo','csv','/nh'],text=True)
    for line in out.splitlines():
        if name.lower() in line.lower(): return int(line.split(',')[1].strip('"'))
    return None
K=int(sys.argv[1],16)
pid=pid_of("Carcelclient.exe")
if not pid: print("no client"); sys.exit()
h=k32.OpenProcess(0x10|0x400,False,pid)
def rd(a,n):
    buf=(C.c_char*n)(); got=C.c_size_t()
    return buf.raw[:got.value] if k32.ReadProcessMemory(h,C.c_void_p(a),buf,n,C.byref(got)) else b''
needle=struct.pack('<I',K)
mbi=MBI(); addr=0; hits=[]
while addr<0x7fff0000:
    if k32.VirtualQueryEx(h,C.c_void_p(addr),C.byref(mbi),C.sizeof(mbi))==0: break
    base=mbi.BaseAddress or 0; size=mbi.RegionSize or 0
    if mbi.State==0x1000 and mbi.Protect in (0x04,0x40,0x02) and size<0x4000000:
        d=rd(base,size); i=0
        while True:
            j=d.find(needle,i)
            if j<0: break
            hits.append(base+j); i=j+1
    addr=base+size
print("key 0x%08x found at %d locations"%(K,len(hits)))
for a in hits:
    conn=a-0x4e   # key is at conn+0x4e
    d=rd(conn,0x60)
    if len(d)<0x60: continue
    c0=struct.unpack('<I',d[0:4])[0]; c4=struct.unpack('<I',d[4:8])[0]
    e12=struct.unpack('<H',d[0x12:0x14])[0]
    e26=struct.unpack('<I',d[0x26:0x2a])[0]
    e2e=struct.unpack('<I',d[0x2e:0x32])[0]
    if c4==0x10000001:
        print("CONN @%08x [0]=%08x [4]=%08x sendCtr(0x12)=%d buf(0x26)=%d recvExp(0x2e)=%d"%(conn,c0,c4,e12,e26,e2e))
