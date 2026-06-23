import pefile, capstone, re
PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH); ib = pe.OPTIONAL_HEADER.ImageBase
data=open(PATH,'rb').read()
text = next(s for s in pe.sections if s.Name.rstrip(b'\x00')==b'.text')
tva=ib+text.VirtualAddress; tdata=text.get_data()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32); md.detail=True
def va_of(fo):
    for s in pe.sections:
        if s.PointerToRawData<=fo<s.PointerToRawData+s.SizeOfRawData: return ib+s.VirtualAddress+(fo-s.PointerToRawData)
def strva(name):
    fo=data.find(name+b'\x00')
    return va_of(fo) if fo>=0 else None
def refs(va):
    if va is None: return []
    needle=va.to_bytes(4,'little'); hits=[]; i=0
    while True:
        i=tdata.find(needle,i)
        if i<0: break
        hits.append(tva+i); i+=1
    return hits
for nm in [b'ROOMREADY',b'PASSDOOR',b'PLAYERDEFINITION',b'PLAYERENTERED',b'CONNECTEDTOSERVER',b'INITIALPARAMS',b'ROOMREADY packet',b'Received NETMSG_ROOMREADY']:
    v=strva(nm)
    print("%-20s VA=%s refs=%s"%(nm.decode(), hex(v) if v else None, [hex(x) for x in refs(v)][:6]))
# also the 'Received %s' style: find 'Received ' format usage near these
