import struct
from minidump.minidumpfile import MinidumpFile
mf = MinidumpFile.parse(r"C:\Users\Administrator\Desktop\PrisonServer\Server\dumps\Carcelclient.exe.15496.dmp")
rdr = mf.get_reader()
def read(a,n):
    try: return rdr.read(a,n)
    except: return b''
# crash thread = the one with esi=3 (the bad strdup ptr)
target=None
for t in mf.threads.threads:
    ctx=getattr(t,'ContextObject',None)
    if ctx and getattr(ctx,'Esi',None)==3 and getattr(ctx,'Edi',None)==0xffffffff:
        target=t; break
if not target:
    print("crash thread not found by esi=3"); 
    for t in mf.threads.threads[:1]: target=t
ctx=target.ContextObject
esp=ctx.Esp; ebp=ctx.Ebp
print("crash thread %x esp=%x ebp=%x eip=%x esi=%x ecx=%x edx=%x"%(target.ThreadId,esp,ebp,ctx.Eip,ctx.Esi,ctx.Ecx,ctx.Edx))
# walk stack: read 0x600 bytes from esp, print dwords that are code addrs in client .text (0x401000-0x5c0000)
data=read(esp,0x800)
print("=== return addresses on stack (client .text 0x401000-0x5c0000) ===")
seen=0
for i in range(0,len(data)-4,4):
    v=struct.unpack('<I',data[i:i+4])[0]
    if 0x401000<=v<0x5c0000:
        print("  esp+%04x: %08x"%(i,v)); seen+=1
        if seen>=30: break
