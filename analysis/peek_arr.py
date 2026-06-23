import ctypes as C, subprocess, time, sys
k32=C.windll.kernel32
def pid_of(n):
    try: out=subprocess.check_output(['tasklist','/fi','imagename eq %s'%n,'/fo','csv','/nh'],text=True)
    except Exception: return None
    for l in out.splitlines():
        if n.lower() in l.lower():
            try: return int(l.split(',')[1].strip('"'))
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
    b=rd(a,4); return int.from_bytes(b,'little') if b else -1
printed=False
t0=time.time()
while time.time()-t0<15:
    arr=rdd(0x5eda70); cnt=rdd(0x5eda6c); screen=rdd(0x5bd448)
    if screen==-1: print("[exited at t+%.2fs]"%(time.time()-t0)); break
    if arr and arr not in (0,0xffffffff) and 0<cnt<10 and not printed:
        print("t+%.2fs srvDataArr=0x%x srvCount=%d screen=0x%x"%(time.time()-t0,arr,cnt,screen))
        for i in range(cnt):
            e=arr+i*0x10
            eid=rdd(e); lenb=rd(e+4,1); namep=rdd(e+8)
            nm=""
            if namep and namep not in(0,0xffffffff):
                raw=rd(namep, (lenb[0] if lenb else 0)*2)
                if raw:
                    try: nm=raw.decode('utf-16le',errors='replace')
                    except Exception: nm=repr(raw)
            print("   entry[%d] id=%d  +4(reclusos byte)=%d  nameUTF16='%s'"%(
                  i,eid,lenb[0] if lenb else -1,nm))
        printed=True
    time.sleep(0.03)
print("done printed=%s"%printed)
