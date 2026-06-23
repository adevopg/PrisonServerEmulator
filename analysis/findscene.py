import os, glob, struct, zlib, re
os.chdir(r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer")

def parse_index(d):
    # walk index entries: [name\0][off:4][unc:4][comp:4][flag:1]; names contain '.R3D' or '.r3d'
    out=[]
    for m in re.finditer(rb'[ -~]{4,}\.[Rr]3[Dd]\x00', d):
        name=m.group()[:-1].decode('latin1')
        e=m.end()  # right after the NUL
        if e+13<=len(d):
            off,unc,comp=struct.unpack('<III', d[e:e+12]); flag=d[e+12]
            if 0<comp<len(d) and 0<off<len(d) and unc<50_000_000:
                out.append((name,off,unc,comp,flag))
    return out

def objnames(blob):
    names=set()
    for m in re.finditer(rb'[A-Za-z][ -~]{2,30}', blob):
        s=m.group().decode('latin1')
        names.add(s)
    return names

best=[]
for p in glob.glob('gfx*.pak')+glob.glob('Gfx*.pak'):
    d=open(p,'rb').read()
    for name,off,unc,comp,flag in parse_index(d):
        if 'nge' not in name.lower(): continue
        if 'puerta' in name.lower() or 'plantilla' in name.lower(): continue
        blob=d[off:off+comp]
        try:
            data = zlib.decompress(blob) if flag==1 else blob
        except: continue
        low=data.lower()
        has_cam = b'camara' in low
        has_suelo = b'suelo' in low
        if has_cam and has_suelo:
            best.append((p,name,len(data)))
            print('HAS BOTH: %-14s %-40s (%d bytes)'%(p,name,len(data)))
print('--- candidates with camera+suelo:',len(best),'---')
