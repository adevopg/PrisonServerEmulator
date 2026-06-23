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
def rdd(a):
    b=(C.c_char*4)(); g=C.c_size_t()
    return int.from_bytes(b.raw,'little') if k32.ReadProcessMemory(h,C.c_void_p(a),b,4,C.byref(g)) else -1
screens=[]; arrseen=set(); recseen=set(); t0=time.time(); lastscreen=None
while time.time()-t0<16:
    sc=rdd(0x5bd448); arr=rdd(0x5eda70); rec=rdd(0x5eda78)
    if sc==-1: print("[exited t+%.2fs]"%(time.time()-t0)); break
    if sc!=lastscreen:
        screens.append((round(time.time()-t0,3),sc)); lastscreen=sc
    if arr not in (0,0xffffffff,-1): arrseen.add(arr)
    if rec not in (0,-1): recseen.add(rec)
    # no sleep -> max frequency
print("screen transitions:", " ".join("t+%.3f=0x%x"%(t,s) for t,s in screens))
print("srvDataArr non-zero values seen:", [hex(x) for x in arrseen])
print("recluCounter non-zero values seen:", sorted(recseen), "(shown:", sorted(x+1 for x in recseen),")")
