import pefile, capstone, re
P=r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe=pefile.PE(P); ib=pe.OPTIONAL_HEADER.ImageBase
data=open(P,'rb').read()
t=next(s for s in pe.sections if s.Name.rstrip(b'\x00')==b'.text'); tva=ib+t.VirtualAddress; td=t.get_data()
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
def fo(va):
    for s in pe.sections:
        a=ib+s.VirtualAddress
        if a<=va<a+s.Misc_VirtualSize: return s.PointerToRawData+(va-a)
def va_of(off):
    for s in pe.sections:
        if s.PointerToRawData<=off<s.PointerToRawData+s.SizeOfRawData: return ib+s.VirtualAddress+(off-s.PointerToRawData)
# find strings containing NGE or .R3D or ESCENA
NGE=b"NGE"+b"\x5c"  # NGE\
fmt=b"\x5c%s.R3D"   # \%s.R3D
for m in re.finditer(rb'[ -~]{4,}', data):
    s=m.group()
    if NGE in s or fmt in s or b'ESCENA' in s.upper() or (b'GFX' in s and b'R3D' in s):
        print('str 0x%08x: %r'%(va_of(m.start()), s[:60]))
