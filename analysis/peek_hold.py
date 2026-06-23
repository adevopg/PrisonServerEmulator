import ctypes as C, subprocess, time, sys
k32=C.windll.kernel32
def pid_of(n):
    try:
        out=subprocess.check_output(['tasklist','/fi','imagename eq %s'%n,'/fo','csv','/nh'],text=True)
    except Exception: return None
    for l in out.splitlines():
        if n.lower() in l.lower():
            try: return int(l.split(',')[1].strip('"'))
            except Exception: pass
    return None

# wait up to 12s for the client to appear
pid=None
for _ in range(120):
    pid=pid_of("Carcelclient.exe")
    if pid: break
    time.sleep(0.1)
if not pid: print("client never appeared"); sys.exit()
print("client pid", pid)
h=k32.OpenProcess(0x10,False,pid)
def rdd(a):
    b=(C.c_char*4)(); g=C.c_size_t()
    return int.from_bytes(b.raw,'little') if k32.ReadProcessMemory(h,C.c_void_p(a),b,4,C.byref(g)) else -1

last=None; seen0xc=False; reclu_at_c=set()
t0=time.time()
while time.time()-t0 < 15:
    screen=rdd(0x5bd448); phase=rdd(0x5eda4c); reclu=rdd(0x5eda78); idx=rdd(0x5eda74)
    if screen==-1: print("[client exited at t+%.2fs] last state: %s"%(time.time()-t0,last)); break
    cur=(screen,phase,idx,reclu)
    if cur!=last:
        print("t+%.2fs screen=0x%x phase=%d selIdx=%d recluCounter=%d (shown=%d)"%(
              time.time()-t0,screen,phase,idx,reclu,reclu+1))
        last=cur
    if screen==0xc:
        seen0xc=True
        if reclu>=0: reclu_at_c.add(reclu)
    time.sleep(0.02)
print("--- reached prison-select(0xc): %s ; recluCounter values seen at 0xc: %s (shown=%s)"%(
      seen0xc, sorted(reclu_at_c), sorted(x+1 for x in reclu_at_c)))
