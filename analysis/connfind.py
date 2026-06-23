import ctypes as C, ctypes.wintypes as W, subprocess, sys, struct
k32=C.windll.kernel32
class MBI(C.Structure):
    _fields_=[("BaseAddress",C.c_void_p),("AllocationBase",C.c_void_p),("AllocationProtect",W.DWORD),
    ("RegionSize",C.c_size_t),("State",W.DWORD),("Protect",W.DWORD),("Type",W.DWORD)]
def pid_of(n):
    out=subprocess.check_output(['tasklist','/fi','imagename eq %s'%n,'/fo','csv','/nh'],text=True)
    for l in out.splitlines():
        if n.lower() in l.lower(): return int(l.split(',')[1].strip('"'))
pid=pid_of("Carcelclient.exe")
if not pid: print("noclient"); sys.exit()
h=k32.OpenProcess(0x10,False,pid)
def rd(a,n):
    b=(C.c_char*n)(); g=C.c_size_t()
    return b.raw[:g.value] if k32.ReadProcessMemory(h,C.c_void_p(a),b,n,C.byref(g)) else b''
cid=struct.pack('<I',0x10000001); ip=0x0100007f
mbi=MBI(); addr=0; conns=[]
while addr<0x7fff0000:
    if k32.VirtualQueryEx(h,C.c_void_p(addr),C.byref(mbi),C.sizeof(mbi))==0: break
    base=mbi.BaseAddress or 0; size=mbi.RegionSize or 0
    if mbi.State==0x1000 and mbi.Protect in (0x04,0x40,0x02) and size<0x4000000:
        d=rd(base,size); i=0
        while True:
            j=d.find(cid,i)
            if j<0: break
            i=j+1
            # candidate conn[4]=cid -> conn=base+j-4 ; check conn[0x16]==ip
            if j>=4 and j-4+0x60<=len(d):
                off=j-4
                c16=struct.unpack('<I',d[off+0x16:off+0x1a])[0]
                if c16==ip:
                    e2e=struct.unpack('<I',d[off+0x2e:off+0x32])[0]
                    e26=struct.unpack('<I',d[off+0x26:off+0x2a])[0]
                    c1a=struct.unpack('<H',d[off+0x1a:off+0x1c])[0]
                    key=struct.unpack('<I',d[off+0x4e:off+0x52])[0]
                    conns.append((base+off,c1a,e2e,e26,key))
    addr=base+size
print("matched conns:",len(conns))
for a,port,e2e,e26,key in conns[:8]:
    print("  conn@%08x port=%d recvExp(0x2e)=%d buf(0x26)=%d key(0x4e)=%08x"%(a,port,e2e,e26,key))
