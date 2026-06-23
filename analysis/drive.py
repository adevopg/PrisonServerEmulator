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
        if p.value==pid and u32.IsWindowVisible(h):
            n=u32.GetWindowTextLengthW(h)
            if n: res.append(h)
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
hwnd=None; last=None; t0=time.time()
while time.time()-t0<25:
    if hwnd is None: hwnd=find_win(pid)
    if hwnd:
        u32.ShowWindow(hwnd,9); u32.SetForegroundWindow(hwnd); u32.BringWindowToTop(hwnd)
    # check process alive
    code=W.DWORD(0); k32.GetExitCodeProcess(h,C.byref(code))
    if code.value!=259:  # STILL_ACTIVE=259
        print("EXITED t+%.1f code=0x%x"%(time.time()-t0, code.value)); break
    sc=rdd(0x5bd448); ph=rdd(0x5eda4c); arr=rdd(0x5ec5d0); srv=rdd(0x5eda70)
    cur=(sc,ph,arr!=0 and arr!=-1,srv!=0 and srv!=-1)
    if cur!=last:
        print("t+%.1f screen=0x%x phase=%s classArr=%s srvArr=%s"%(time.time()-t0,sc if sc!=-1 else -1,ph,hex(arr) if arr not in(0,-1) else 0,hex(srv) if srv not in(0,-1) else 0))
        last=cur
    time.sleep(0.15)
print("end")
