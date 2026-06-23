import ctypes as C, subprocess, time, sys
from ctypes import wintypes as W
u32=C.windll.user32; k32=C.windll.kernel32
u32.SetProcessDPIAware()
def pid_of(n):
    try: out=subprocess.check_output(["tasklist","/fi","imagename eq %s"%n,"/fo","csv","/nh"],text=True)
    except Exception: return None
    for l in out.splitlines():
        if n.lower() in l.lower():
            try: return int(l.split(",")[1].strip('"'))
            except Exception: pass
    return None
def find_win(pid):
    res=[]
    @C.WINFUNCTYPE(C.c_bool, W.HWND, W.LPARAM)
    def cb(h,l):
        p=W.DWORD(0); u32.GetWindowThreadProcessId(h,C.byref(p))
        if p.value==pid and u32.IsWindowVisible(h) and u32.GetWindowTextLengthW(h)>0: res.append(h)
        return True
    u32.EnumWindows(cb,0); return res[0] if res else None
pid=None
for _ in range(80):
    pid=pid_of("Carcelclient.exe")
    if pid: break
    time.sleep(0.1)
if not pid: print("no client"); sys.exit()
print("pid",pid)
h=k32.OpenProcess(0x10,False,pid)
def rdd(a):
    b=(C.c_char*4)(); g=C.c_size_t()
    return int.from_bytes(b.raw,"little") if k32.ReadProcessMemory(h,C.c_void_p(a),b,4,C.byref(g)) else -1
def rstr(a,mx=32):
    if a in (0,0xffffffff,-1): return None
    b=(C.c_char*mx)(); g=C.c_size_t()
    if not k32.ReadProcessMemory(h,C.c_void_p(a),b,mx,C.byref(g)): return None
    z=b.raw.find(b"\0"); return b.raw[:z if z>=0 else mx].decode("latin1","replace")
hwnd=None; t0=time.time(); best=None
while time.time()-t0<22:
    if hwnd is None: hwnd=find_win(pid)
    if hwnd: u32.SetForegroundWindow(hwnd); u32.BringWindowToTop(hwnd)
    code=W.DWORD(0); k32.GetExitCodeProcess(h,C.byref(code))
    if code.value!=259: print("EXITED t+%.1f code=0x%x"%(time.time()-t0,code.value)); break
    N0=rdd(0x5c2b3c); arr=rdd(0x5ec5d0)
    if 0<N0<200 and arr not in (0,-1,0xffffffff):
        nm=rstr(rdd(arr+0))  # entry+0 name
        msg="*** CLASSINFO OK t+%.1f N0=%d classArr=0x%x class[0]+0='%s'"%(time.time()-t0,N0,arr,nm)
        if msg!=best: print(msg); best=msg
    time.sleep(0.1)
print("end. best:",best)
