# Non-intrusive memory reader (PROCESS_VM_READ only, no debugger -> no anti-debug).
# Polls key client globals to observe screen/login state while it runs vs our server.
import ctypes as C, ctypes.wintypes as W, sys, time
k32=C.windll.kernel32
PROCESS_VM_READ=0x10; PROCESS_QUERY_INFORMATION=0x400
def pid_of(name):
    import subprocess
    out=subprocess.check_output(['tasklist','/fi','imagename eq %s'%name,'/fo','csv','/nh'],text=True)
    for line in out.splitlines():
        if name.lower() in line.lower():
            return int(line.split(',')[1].strip('"'))
    return None
def main():
    name="Carcelclient.exe"
    pid=None
    for _ in range(40):
        pid=pid_of(name)
        if pid: break
        time.sleep(0.25)
    if not pid: print("client not found"); return
    h=k32.OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION,False,pid)
    if not h: print("OpenProcess failed",k32.GetLastError()); return
    print("attached pid",pid)
    GLOB={0x5bd448:"screenState",0x5be628:"updFlag",0x5be62c:"acctPtr",0x5eda4c:"loginPhase",0x5bdc68:"menuState"}
    def rd(a,n=4):
        buf=(C.c_char*n)(); got=C.c_size_t()
        ok=k32.ReadProcessMemory(h,C.c_void_p(a),buf,n,C.byref(got))
        return int.from_bytes(buf.raw[:got.value],'little') if ok else None
    last=None
    for i in range(60):
        vals={n:rd(a) for a,n in GLOB.items()}
        line=" ".join("%s=%s"%(n,("%x"%v if v is not None else "?")) for n,v in vals.items())
        if line!=last: print("[%2d] %s"%(i,line)); sys.stdout.flush(); last=line
        if vals.get("screenState")==0xc: print(">>> SERVER-SELECT SCREEN (0xc) REACHED <<<");
        time.sleep(0.5)
main()
