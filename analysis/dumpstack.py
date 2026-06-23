import glob, os
from minidump.minidumpfile import MinidumpFile
dumps=sorted(glob.glob(r"c:\Users\Administrator\Desktop\PrisonServer\Server\dumps\*.dmp"), key=os.path.getmtime)
path=dumps[-1]; print("dump:",os.path.basename(path))
mf=MinidumpFile.parse(path)
rec=mf.exception.exception_records[0]; ER=rec.ExceptionRecord
print("excAddr=0x%08x flags=0x%x params=%s tid=0x%x"%(
    ER.ExceptionAddress, ER.ExceptionFlags, [hex(x) for x in ER.ExceptionInformation], rec.ThreadId))
def in_text(v): return 0x401000<=v<0x600000
for t in mf.threads.threads:
    if t.ThreadId!=rec.ThreadId: continue
    base=t.Stack.StartOfMemoryRange; size=t.Stack.MemoryLocation.DataSize
    print("stack base=0x%x size=0x%x"%(base,size))
    r=mf.get_reader()
    try: data=r.read(base,size)
    except Exception:
        rr=r.get_buffered_reader() if hasattr(r,'get_buffered_reader') else r
        rr.move(base); data=rr.read(size)
    print("--- Carcelclient code addresses on stack (top 50) ---")
    cnt=0
    for i in range(0,len(data)-4,4):
        v=int.from_bytes(data[i:i+4],'little')
        if in_text(v):
            print("  [+0x%05x] 0x%08x"%(i,v)); cnt+=1
            if cnt>=50: break
    break
