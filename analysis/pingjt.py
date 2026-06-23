import pefile, capstone, struct
PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH); ib = pe.OPTIONAL_HEADER.ImageBase
def rva_data(va,n):
    return pe.get_data(va-ib, n)
idxtab = rva_data(0x4bedcc, 0x1a)   # 26 byte indices
addrs=[]
raw=rva_data(0x4bed88, 0x1a*4)      # assume up to 0x1a entries; we'll read max index+1
maxidx=max(idxtab)
addrtab=rva_data(0x4bed88,(maxidx+1)*4)
ptrs=[struct.unpack('<I',addrtab[i*4:i*4+4])[0] for i in range(maxidx+1)]
print("event  idx  handler")
for e in range(0x1a):
    idx=idxtab[e]
    print("0x%04x  %2d   0x%08x"%(0x40b+e, idx, ptrs[idx]))
