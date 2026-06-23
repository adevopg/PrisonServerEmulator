import glob, os, re, struct
os.chdir(r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer")
target=b"COMBATEpatio.R3D"
for p in glob.glob('*.pak'):
    d=open(p,'rb').read()
    idx=d.lower().find(target.lower())
    if idx<0: continue
    print("=== %s  size=%d  found '%s' @0x%x ===" % (p,len(d),target.decode(),idx))
    # header
    print("header:", d[:0x18])
    # bytes around the filename entry (0x30 before, name, 0x20 after)
    s=max(0,idx-0x30)
    region=d[s:idx+len(target)+0x20]
    # hex view
    for off in range(0,len(region),16):
        chunk=region[off:off+16]
        hexs=' '.join('%02x'%b for b in chunk)
        asc=''.join(chr(b) if 32<=b<127 else '.' for b in chunk)
        print('  %08x: %-48s %s'%(s+off, hexs, asc))
    # try to see if there's a count/index table at start: read some dwords after header
    print("dwords @0x10:", struct.unpack('<8I', d[0x10:0x30]))
    break
