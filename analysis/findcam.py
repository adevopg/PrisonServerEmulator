import os, glob, struct, zlib, re, sys
sys.path.insert(0, r"c:\Users\Administrator\Desktop\PrisonServer\Server\analysis")
from findscene import parse_index
os.chdir(r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer")

camobj = re.compile(rb'[Cc]amara[0-9]{1,2}\x00')  # camera OBJECT name, null-terminated
found = []
for p in glob.glob('*.pak'):
    d = open(p, 'rb').read()
    for name, off, unc, comp, flag in parse_index(d):
        if not name.lower().endswith('.r3d'):
            continue
        blob = d[off:off+comp]
        try:
            data = zlib.decompress(blob) if flag == 1 else blob
        except Exception:
            continue
        m = camobj.search(data)
        if m:
            cams = sorted(set(x.group().decode('latin1') for x in camobj.finditer(data)))
            print('CAM OBJECT in %-12s %-44s cams=%s (%db, flag=%d)' % (p, name, cams[:5], len(data), flag))
            found.append((p, name, off, unc, comp, flag))
print('--- total .R3D with a real camera object:', len(found), '---')
