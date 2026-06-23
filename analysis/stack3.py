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
data=read(esp,0x1200)
for i in range(0,len(data)-4,4):
    if struct.unpack('<I',data[i:i+4])[0]==0x452ab0:
        eip_addr=esp+i
        # validate CONTEXT: Esi (eip-0x18) should be 3
        esi_b=read(eip_addr-0x18,4)
        esi=struct.unpack('<I',esi_b)[0] if len(esi_b)==4 else -1
        esp_b=read(eip_addr+0xc,4)   # Esp at Eip+0xc (0xc4-0xb8)
        oesp=struct.unpack('<I',esp_b)[0] if len(esp_b)==4 else 0
        tag = " <<<CONTEXT(esi=3)" if esi==3 else ""
        print("Eip@%x  esi(-0x18)=%x  Esp(+0xc)=%x%s"%(eip_addr,esi,oesp,tag))
        if esi==3 and oesp:
            sd=read(oesp,0xa0)
            print("   original stack (.text return addrs):")
            for j in range(0,len(sd)-4,4):
                rv=struct.unpack('<I',sd[j:j+4])[0]
                if 0x401000<=rv<0x5c0000: print("     oEsp+%x: %08x"%(j,rv))
