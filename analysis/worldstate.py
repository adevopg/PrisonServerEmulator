import pefile, capstone, re
PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH); ib = pe.OPTIONAL_HEADER.ImageBase
data_all=open(PATH,'rb').read()
text = next(s for s in pe.sections if s.Name.rstrip(b'\x00')==b'.text')
tva=ib+text.VirtualAddress; tdata=text.get_data()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32); md.detail=True
def va_of(fo):
    for s in pe.sections:
        if s.PointerToRawData<=fo<s.PointerToRawData+s.SizeOfRawData:
            return ib+s.VirtualAddress+(fo-s.PointerToRawData)
    return None
# find the world state strings
for pat in [rb'ENTRADA SOLICITADA', rb'CONECTADO AL SERVIDOR', rb'Imposible conectar', rb'ESPERANDO', rb'ENTRANDO']:
    for m in re.finditer(pat, data_all):
        va=va_of(m.start())
        print("str 0x%08x : %s"%(va, data_all[m.start():m.start()+40].split(b'\x00')[0]))
# map world opcodes 0x138e/0x1477/0x1388 to handlers (same dispatch table)
btbl=pe.get_data(0x40c748-ib,0x7d); maxidx=max(btbl); dtbl=pe.get_data(0x40c6e8-ib,(maxidx+1)*4)
def handler(w):
    r=w-0x1388
    if not (1<=r<=0x7d): return None
    idx=btbl[r-1]; return int.from_bytes(dtbl[idx*4:idx*4+4],'little')
for w in (0x1388,0x138e,0x138f,0x1390,0x1477,0x1478,0x13f2,0x138d):
    h=handler(w); print("world opcode 0x%04x -> handler %s"%(w, hex(h) if h else 'n/a'))
