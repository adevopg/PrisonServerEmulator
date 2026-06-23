import os, sys, struct, zlib, glob
os.chdir(r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer")

def find_entry(packdata, name_bytes):
    # index entry: [name\0][offset:4][uncompsize:4][compsize:4][flag:1]
    low=packdata.lower(); nl=name_bytes.lower()
    i=0
    while True:
        i=low.find(nl, i)
        if i<0: return None
        # require the byte right after name to be 0 (asciiz terminator) and preceding byte be 0 or '\\'
        end=i+len(name_bytes)
        if packdata[end:end+1]==b'\x00':
            off,unc,comp = struct.unpack('<III', packdata[end+1:end+13])
            flag=packdata[end+13]
            return off,unc,comp,flag
        i=end

def extract(packfile, name, outpath):
    d=open(packfile,'rb').read()
    e=find_entry(d, name.encode())
    if not e:
        print("NOT FOUND %s in %s"%(name,packfile)); return False
    off,unc,comp,flag=e
    print("%s: off=0x%x uncomp=%d comp=%d flag=%d"%(name,off,unc,comp,flag))
    blob=d[off:off+comp]
    if flag==1:
        out=zlib.decompress(blob)
    else:
        out=blob
    assert len(out)==unc, "size mismatch %d!=%d"%(len(out),unc)
    os.makedirs(os.path.dirname(outpath), exist_ok=True)
    open(outpath,'wb').write(out)
    print("WROTE %s (%d bytes)"%(outpath,len(out)))
    return True

if __name__=='__main__':
    # COMBATEpatio.R3D lives in gfx5.pak -> place as GFX\NGE\PATIO.R3D (loose, decompressed)
    name=sys.argv[1] if len(sys.argv)>1 else "COMBATEpatio.R3D"
    outp=sys.argv[2] if len(sys.argv)>2 else r"GFX\NGE\PATIO.R3D"
    found=False
    for p in glob.glob('*.pak'):
        if find_entry(open(p,'rb').read(), name.encode()):
            found=extract(p, name, outp); break
    if not found: print("could not extract", name)
