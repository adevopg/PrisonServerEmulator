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
pid=None
for _ in range(60):
    pid=pid_of("Carcelclient.exe")
    if pid: break
    time.sleep(0.25)
if not pid: print("no client"); sys.exit()
h=k32.OpenProcess(0x10|0x400,False,pid)
print("pid",pid)
def rd(a,n):
    buf=(C.c_char*n)(); got=C.c_size_t()
    ok=k32.ReadProcessMemory(h,C.c_void_p(a),buf,n,C.byref(got))
    return buf.raw[:got.value] if ok else b''
time.sleep(8)  # let login + our responses happen
# scan committed RW regions for connId 0x10000001
needle=struct.pack('<I',0x10000001)
mbi=MBI(); addr=0; found=[]
while addr < 0x7fff0000:
    if k32.VirtualQueryEx(h,C.c_void_p(addr),C.byref(mbi),C.sizeof(mbi))==0: break
    base=mbi.BaseAddress or 0; size=mbi.RegionSize or 0
    if mbi.State==0x1000 and (mbi.Protect in (0x04,0x40,0x02)) and size< 0x4000000:
        data=rd(base,size)
        i=0
        while True:
            j=data.find(needle,i)
            if j<0: break
            found.append(base+j); i=j+1
    addr=base+size
    if len(found)>4000: break
print("connId occurrences:",len(found))
# For each occurrence, treat as conn[4] -> conn=addr-4, read 0x2e,0x26,0x12 and check key at +0x4e
cands=0
for a in found:
    conn=a-4
    d=rd(conn,0x60)
    if len(d)<0x60: continue
    c0=struct.unpack('<I',d[0:4])[0]
    c4=struct.unpack('<I',d[4:8])[0]
    e2e=struct.unpack('<I',d[0x2e:0x32])[0]
    e26=struct.unpack('<I',d[0x26:0x2a])[0]
    e12=struct.unpack('<I',d[0x12:0x16])[0]
    key=struct.unpack('<I',d[0x4e:0x52])[0]
    # heuristic: a real conn has small counters
    if c4==0x10000001 and (e2e<0x100) and (e12<0x100):
        print("CONN @%08x  [0]=%08x [4]=%08x  recvExp(0x2e)=%d buf(0x26)=%d sendCtr(0x12)=%d key(0x4e)=%08x"%(
            conn,c0,c4,e2e,e26,e12,key))
        cands+=1
        if cands>=6: break
