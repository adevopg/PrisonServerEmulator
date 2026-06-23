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
page=int(k32.VirtualAllocEx(h,None,0x1000,0x3000,0x40))
def R32(a):
    b=(C.c_char*4)(); g=C.c_size_t(); k32.ReadProcessMemory(h,C.c_void_p(a),b,4,C.byref(g)); return struct.unpack('<I',b.raw)[0]
def WB(a,bs):
    old=W.DWORD(0); k32.VirtualProtectEx(h,C.c_void_p(a),len(bs),0x40,C.byref(old))
    buf=C.create_string_buffer(bytes(bs),len(bs)); w=C.c_size_t(); k32.WriteProcessMemory(h,C.c_void_p(a),buf,len(bs),C.byref(w))
    k32.VirtualProtectEx(h,C.c_void_p(a),len(bs),old,C.byref(old)); k32.FlushInstructionCache(h,C.c_void_p(a),len(bs))
marker=page; stub=page+0x10
def rel(frm,to): return (to-(frm+5))&0xffffffff
def relj(frm,to): return (to-(frm+6))&0xffffffff   # for 0f 8x (6 bytes)
b=bytes([0x8b,0x0c,0x24])                      # mov ecx,[esp]
b+=bytes([0x89,0x0d])+struct.pack('<I',marker) # mov [marker],ecx
b+=bytes([0x8b,0x07,0x85,0xc0])                # mov eax,[edi]; test eax,eax
je_at=stub+len(b)
b+=bytes([0x0f,0x84])+struct.pack('<I',relj(je_at,0x452aa5))  # je 0x452aa5
jmp_at=stub+len(b)
b+=bytes([0xe9])+struct.pack('<I',rel(jmp_at,0x452a96))       # jmp 0x452a96
WB(stub,b)
WB(0x452a90, bytes([0xe9])+struct.pack('<I',rel(0x452a90,stub))+bytes([0x90]))
print("injected; capturing strdup caller"); sys.stdout.flush()
dur=float(sys.argv[1]) if len(sys.argv)>1 else 12
t0=time.time(); last=0
while time.time()-t0<dur:
    v=R32(marker)
    if v!=last: last=v
    time.sleep(0.05)
print("LAST strdup caller (ret addr) = %08x"%R32(marker))
