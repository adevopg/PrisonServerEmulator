import ctypes as C, subprocess, time, sys
k32=C.windll.kernel32
def pid_of(n):
    try: out=subprocess.check_output(["tasklist","/fi","imagename eq %s"%n,"/fo","csv","/nh"],text=True)
    except Exception: return None
    for l in out.splitlines():
        if n.lower() in l.lower():
            try: return int(l.split(",")[1].strip('"'))
            except Exception: pass
    return None
pid=None
for _ in range(150):
    pid=pid_of("Carcelclient.exe")
    if pid: break
    time.sleep(0.1)
if not pid: print("client never appeared"); sys.exit()
print("client pid",pid)
h=k32.OpenProcess(0x10,False,pid)
def rd(a,n):
    b=(C.c_char*n)(); g=C.c_size_t()
    return b.raw if k32.ReadProcessMemory(h,C.c_void_p(a),b,n,C.byref(g)) else None
def rdd(a):
    b=rd(a,4); return int.from_bytes(b,"little") if b else -1
def rstr(a,mx=64):
    if a in (0,0xffffffff,-1): return "<null>"
    b=rd(a,mx)
    if not b: return "<unreadable>"
    z=b.find(b"\x00");
    return b[:z if z>=0 else mx].decode("latin1","replace")
done=False
t0=time.time()
while time.time()-t0<15:
    arr=rdd(0x5ec5d0); N0=rdd(0x5c2b3c); N1=rdd(0x5c2b00); N2=rdd(0x5c2b28); screen=rdd(0x5bd448)
    if screen==-1: print("[exited t+%.2f]"%(time.time()-t0)); break
    if arr not in (0,0xffffffff,-1) and 0<N0<64 and not done:
        print("t+%.2f classArr=0x%x N0=%d N1=%d N2=%d screen=0x%x"%(time.time()-t0,arr,N0,N1,N2,screen))
        # attribute names arr1, skill names arr2
        a1=rdd(0x5ec5d4); a2=rdd(0x5ec5d8)
        if a1 not in(0,-1): print("  attrs:", [rstr(rdd(a1+i*4)) for i in range(max(0,min(N1,8)))])
        if a2 not in(0,-1): print("  skills:",[rstr(rdd(a2+i*4)) for i in range(max(0,min(N2,8)))])
        for i in range(min(N0,8)):
            e=arr+i*0x14
            print("  class[%d] +4='%s' +0='%s'"%(i, rstr(rdd(e+4)), rstr(rdd(e))))
        done=True
    time.sleep(0.05)
print("done populated=%s"%done)
