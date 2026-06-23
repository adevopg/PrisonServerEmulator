import struct
from minidump.minidumpfile import MinidumpFile
mf = MinidumpFile.parse(r"C:\Users\Administrator\Desktop\PrisonServer\Server\dumps\Carcelclient.exe.15496.dmp")
rdr = mf.get_reader()
def read(a,n):
    try: return rdr.read(a,n)
    except: return b''
target=None
for t in mf.threads.threads:
    ctx=getattr(t,'ContextObject',None)
    if ctx and getattr(ctx,'Esi',None)==3: target=t; break
esp=target.ContextObject.Esp
data=read(esp,0x800)
print("read len",len(data),"esp=%x"%esp)
# find every 0x452ab0 -> treat as CONTEXT.Eip, extract CONTEXT.Esp(+0xc) & Esi(-0x18)
for i in range(0,len(data)-4,4):
    if struct.unpack('<I',data[i:i+4])[0]==0x452ab0:
        esi = struct.unpack('<I',data[i-0x18:i-0x14])[0] if i>=0x18 else -1
        oesp = struct.unpack('<I',data[i+0xc:i+0x10])[0] if i+0x10<=len(data) else 0
        print("Eip@esp+%x esi=%x origEsp=%x"%(i,esi,oesp))
        if oesp:
            sd=read(oesp,0xc0)
            chain=[]
            for j in range(0,len(sd)-4,4):
                rv=struct.unpack('<I',sd[j:j+4])[0]
                if 0x401000<=rv<0x5c0000: chain.append((j,rv))
            for j,rv in chain[:12]: print("   origEsp+%x: %08x"%(j,rv))
