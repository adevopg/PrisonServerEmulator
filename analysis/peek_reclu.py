import ctypes as C, subprocess, sys
k32=C.windll.kernel32
def pid_of(n):
    out=subprocess.check_output(['tasklist','/fi','imagename eq %s'%n,'/fo','csv','/nh'],text=True)
    for l in out.splitlines():
        if n.lower() in l.lower(): return int(l.split(',')[1].strip('"'))
pid=pid_of("Carcelclient.exe")
if not pid: print("noclient"); sys.exit()
h=k32.OpenProcess(0x10,False,pid)
def rd(a,n=4):
    b=(C.c_char*n)(); g=C.c_size_t()
    if k32.ReadProcessMemory(h,C.c_void_p(a),b,n,C.byref(g)): return b.raw
    return None
def rdd(a):
    b=rd(a,4); return int.from_bytes(b,'little') if b else -1
screen=rdd(0x5bd448); phase=rdd(0x5eda4c); count=rdd(0x5eda6c)
arr=rdd(0x5eda70); idx=rdd(0x5eda74); reclu=rdd(0x5eda78)
print("screen=0x%x loginPhase=%d srvCount=%d srvDataArr=0x%x selIdx=%d recluCounter=%d (shown=%d)"%(
      screen,phase,count,arr,idx,reclu,reclu+1))
# read the selected entry's +4 length/reclusos byte directly
if arr and arr!=0xffffffff and 0<=idx<8:
    entry=arr+idx*0x10
    eid=rdd(entry); lenb=rd(entry+4,1)
    print("  entry[%d] id=%d  +4(byte)=%d"%(idx,eid,lenb[0] if lenb else -1))
