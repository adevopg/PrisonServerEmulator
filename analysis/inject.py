import ctypes as C, ctypes.wintypes as W, subprocess, time, sys, struct
k32=C.windll.kernel32; k32.VirtualAllocEx.restype=C.c_void_p
def pid_of(n):
    out=subprocess.check_output(['tasklist','/fi','imagename eq %s'%n,'/fo','csv','/nh'],text=True)
    for l in out.splitlines():
        if n.lower() in l.lower(): return int(l.split(',')[1].strip('"'))
pid=None
for _ in range(60):
    pid=pid_of("Carcelclient.exe")
    if pid: break
    time.sleep(0.2)
if not pid: print("noclient"); sys.exit()
h=k32.OpenProcess(0x08|0x10|0x20|0x400,False,pid)
page=k32.VirtualAllocEx(h,None,0x1000,0x3000,0x40)  # RWX
page=int(page)
def W32(a,v):
    b=C.create_string_buffer(struct.pack('<I',v&0xffffffff),4); w=C.c_size_t(); k32.WriteProcessMemory(h,C.c_void_p(a),b,4,C.byref(w))
def R32(a):
    b=(C.c_char*4)(); g=C.c_size_t(); k32.ReadProcessMemory(h,C.c_void_p(a),b,4,C.byref(g)); return struct.unpack('<I',b.raw)[0]
def WB(a,bs):
    old=W.DWORD(0); k32.VirtualProtectEx(h,C.c_void_p(a),len(bs),0x40,C.byref(old))
    buf=C.create_string_buffer(bytes(bs),len(bs)); w=C.c_size_t(); k32.WriteProcessMemory(h,C.c_void_p(a),buf,len(bs),C.byref(w))
    k32.VirtualProtectEx(h,C.c_void_p(a),len(bs),old,C.byref(old)); k32.FlushInstructionCache(h,C.c_void_p(a),len(bs))
m1=page; m2=page+4               # markers
W32(m1,0); W32(m2,0)
s1=page+0x40                     # stub1 for 0x40a59e
s2=page+0x80                     # stub2 for 0x413d0c
def rel(frm,to): return (to-(frm+5))&0xffffffff
# stub1: mov [m1],0xAA ; push 0x9cd ; jmp 0x40a5a3
b1 = bytes([0xC7,0x05])+struct.pack('<I',m1)+struct.pack('<I',0xAA)
b1+= bytes([0x68,0xcd,0x09,0x00,0x00])
jb1 = s1+len(b1)
b1+= bytes([0xE9])+struct.pack('<I', rel(jb1,0x40a5a3))
WB(s1,b1)
WB(0x40a59e, bytes([0xE9])+struct.pack('<I', rel(0x40a59e,s1)))
# stub2: mov [m2],0xBB ; call 0x40ea10 ; jmp 0x413d11
b2 = bytes([0xC7,0x05])+struct.pack('<I',m2)+struct.pack('<I',0xBB)
callsite = s2+len(b2)
b2+= bytes([0xE8])+struct.pack('<I', rel(callsite,0x40ea10))
jb2 = s2+len(b2)
b2+= bytes([0xE9])+struct.pack('<I', rel(jb2,0x413d11))
WB(s2,b2)
WB(0x413d0c, bytes([0xE9])+struct.pack('<I', rel(0x413d0c,s2)))
print("injected stubs page=%08x"%page); sys.stdout.flush()
dur=float(sys.argv[1]) if len(sys.argv)>1 else 14
t0=time.time(); last=(0,0)
while time.time()-t0<dur:
    cur=(R32(m1),R32(m2))
    if cur!=last: print("markers: acct(0x40a59e)=%02x reassembly(0x413d0c)=%02x"%cur); sys.stdout.flush(); last=cur
    time.sleep(0.1)
print("FINAL acct=%02x reassembly=%02x"%(R32(m1),R32(m2)))
