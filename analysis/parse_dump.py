import sys, struct
from minidump.minidumpfile import MinidumpFile
mf = MinidumpFile.parse(r"C:\Users\Administrator\Desktop\PrisonServer\Server\dumps\Carcelclient.exe.15496.dmp")
rdr = mf.get_reader()
# exception info
exc = mf.exception
print("=== exception ===")
try:
    e=exc.exception_records[0]
    print("threadId=%x code=%08x addr=%x"%(e.ThreadId, e.ExceptionRecord.ExceptionCode & 0xffffffff, e.ExceptionRecord.ExceptionAddress))
    crash_tid=e.ThreadId
except Exception as ex:
    print("exc parse:",ex); crash_tid=None
# find crashing thread context
def read(addr,n):
    try: return rdr.read(addr,n)
    except: return b''
print("=== threads / contexts ===")
for t in mf.threads.threads:
    if crash_tid and t.ThreadId!=crash_tid: continue
    print("thread %x  Teb=%x"%(t.ThreadId, t.Teb))
    # context: try to get registers
    ctx=None
    try: ctx=t.ContextObject
    except: pass
    if ctx is None:
        # raw context blob
        loc=t.ThreadContext
        blob=read(loc.Rva if hasattr(loc,'Rva') else 0,0)
    # print available attrs
    for r in ('Eip','Eax','Ebx','Ecx','Edx','Esi','Edi','Esp','Ebp','Rip','Rax','Rsi','Rsp'):
        v=getattr(ctx,r,None) if ctx else None
        if v is not None: print("   %s=%x"%(r,v))
