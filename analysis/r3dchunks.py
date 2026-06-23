import sys, struct, glob, os
# Decode .R3D chunk stream like the parser: header preamble, then [id:2][size:4][data], next=off+size, until id==0xff
def decode(path, start=0x40, limit=60):
    d = open(path, 'rb').read()
    print('=== %s  (size %d) ===' % (os.path.basename(path), len(d)))
    print('  preamble[0:0x40]:', ' '.join('%02x' % b for b in d[:0x40]))
    off = start
    n = 0
    while off + 6 <= len(d) and n < limit:
        cid, csz = struct.unpack('<H', d[off:off+2])[0], struct.unpack('<I', d[off+2:off+6])[0]
        # peek name (printable run right after the 6-byte header)
        name = ''
        j = off + 6
        while j < len(d) and 32 <= d[j] < 127 and j < off+6+24:
            name += chr(d[j]); j += 1
        typ = {0x4000:'CAMERA',0x5000:'MESH',0x1100:'MATERIAL',0x2000:'OBJ',0x2500:'?2500',0xff:'END',0xcabe:'MAGIC'}.get(cid,'?')
        print('  @0x%05x id=0x%04x size=0x%-6x (%6d) %-8s %r' % (off, cid, csz, csz, typ, name[:20]))
        if cid == 0xff or csz == 0:
            print('  -- END --'); break
        if csz < 6 or off+csz > len(d):
            print('  !! bad size, would desync/overrun (off+size=0x%x > 0x%x)' % (off+csz, len(d))); break
        off += csz
        n += 1

if __name__ == '__main__':
    for p in sys.argv[1:]:
        decode(p)
        print()
