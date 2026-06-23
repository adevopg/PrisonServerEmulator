import struct
from minidump.minidumpfile import MinidumpFile
mf = MinidumpFile.parse(r"C:\Users\Administrator\Desktop\PrisonServer\Server\dumps\Carcelclient.exe.15496.dmp")
rdr = mf.get_reader()
def read(a,n):
    try: return rdr.read(a,n)
    except: return b''
# crash thread
target=None
for t in mf.threads.threads:
    ctx=getattr(t,'ContextObject',None)
    if ctx and getattr(ctx,'Esi',None)==3: target=t; break
ctx=target.ContextObject; esp=ctx.Esp
data=read(esp,0x1000)
# find CONTEXT records: Eip field (0xb8) == 0x452ab0 -> original Esp at +0xc4
print("=== saved CONTEXTs (Eip=0x452ab0) and original Esp + caller ===")
for i in range(0,len(data)-4,4):
    v=struct.unpack('<I',data[i:i+4])[0]
    if v==0x452ab0:
        ctxbase=esp+i-0xb8
        cd=read(ctxbase,0xcc)
        if len(cd)>=0xcc:
            oesp=struct.unpack('<I',cd[0xc4:0xc8])[0]
            oesi=struct.unpack('<I',cd[0xa0:0xa4])[0]
            print("CONTEXT@%x origEsp=%x esi=%x"%(ctxbase,oesp,oesi))
            # walk original stack: first 16 dwords, show .text return addrs
            sd=read(oesp,0x80)
            for j in range(0,len(sd)-4,4):
                rv=struct.unpack('<I',sd[j:j+4])[0]
                if 0x401000<=rv<0x5c0000:
                    print("   origEsp+%x: %08x"%(j,rv))
        break
