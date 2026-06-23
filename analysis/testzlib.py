import zlib

# Mirror of zlibStore() in sns_login_server.cpp
def adler32(d):
    a=1;b=0
    for x in d:
        a=(a+x)%65521; b=(b+a)%65521
    return (b<<16)|a
def zlibStore(data):
    out=bytearray()
    out += bytes([0x78,0x01])
    pos=0; n=len(data)
    while True:
        chunk=min(n-pos,0xFFFF); last=(pos+chunk>=n)
        out += bytes([1 if last else 0])
        out += bytes([chunk&0xff,(chunk>>8)&0xff])
        out += bytes([(~chunk)&0xff,((~chunk)>>8)&0xff])
        out += data[pos:pos+chunk]
        pos+=chunk
        if pos>=n: break
    ad=adler32(data)
    out += bytes([(ad>>24)&0xff,(ad>>16)&0xff,(ad>>8)&0xff,ad&0xff])
    return bytes(out)

# Build the same CLASSINFO blob the server builds (N0=32, name="Recluso", N1=N2=0)
def putstr(buf,s):
    buf.append(len(s)); buf+=s.encode('latin1')
N0=32; NM="Recluso"
blob=bytearray(); blob+=bytes([N0,0,0])
for c in range(N0):
    putstr(blob,NM); putstr(blob,NM); putstr(blob,"")
    blob+=bytes(20)
print("blob len",len(blob))
comp=zlibStore(blob)
print("comp len",len(comp), "first bytes", comp[:8].hex())
# verify python zlib can inflate it (like the client's uncompress)
try:
    dec=zlib.decompress(comp)
    print("DECOMPRESS OK, len",len(dec), "matches:", dec==bytes(blob))
except Exception as e:
    print("DECOMPRESS FAILED:", e)
# also test the tiny stub [32,0,0]
stub=bytes([32,0,0]); cs=zlibStore(stub)
try:
    print("stub decompress:", zlib.decompress(cs)==stub)
except Exception as e:
    print("stub FAILED:", e)
