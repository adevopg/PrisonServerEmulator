import ctypes as C, ctypes.wintypes as W, sys, subprocess, struct
k32=C.windll.kernel32
class MBI(C.Structure):
    _fields_=[("BaseAddress",C.c_void_p),("AllocationBase",C.c_void_p),("AllocationProtect",W.DWORD),
    ("RegionSize",C.c_size_t),("State",W.DWORD),("Protect",W.DWORD),("Type",W.DWORD)]
def pid_of(n):
    out=subprocess.check_output(['tasklist','/fi','imagename eq %s'%n,'/fo','csv','/nh'],text=True)
    for l in out.splitlines():
        if n.lower() in l.lower(): return int(l.split(',')[1].strip('"'))
K=int(sys.argv[1],16)
pid=pid_of("Carcelclient.exe"); h=k32.OpenProcess(0x10|0x400,False,pid)
def rd(a,n):
    b=(C.c_char*n)(); g=C.c_size_t()
    return b.raw[:g.value] if k32.ReadProcessMemory(h,C.c_void_p(a),b,n,C.byref(g)) else b''
needle=struct.pack('<I',K); cid=struct.pack('<I',0x10000001)
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
print("K hits:",[hex(x) for x in hits])
for a in hits:
    base=a-0x50
    d=rd(base,0xa0)
    print("\n--- around K@%08x (dump from %08x) ---"%(a,base))
    for off in range(0,0xa0,16):
        row=d[off:off+16]
        # mark where connId 0x10000001 appears
        print("  +%03x: %s"%(base+off-a, ' '.join('%02x'%x for x in row)))
    # find connId near
    j=d.find(cid)
    if j>=0: print("  connId 0x10000001 at offset %+d from K"%(base+j-a))
