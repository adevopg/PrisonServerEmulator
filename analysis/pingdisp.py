import pefile, capstone
PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH); ib = pe.OPTIONAL_HEADER.ImageBase
text=[s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text'][0]
tva=ib+text.VirtualAddress; td=text.get_data()
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
def ctx(va,back=6,fwd=8):
    off=va-tva-back
    for ins in md.disasm(td[off:off+back+fwd], tva+off):
        if ins.address<=va<=ins.address+ins.size:
            return "%08x: %-8s %s"%(ins.address,ins.mnemonic,ins.op_str)
    return "%08x: ?"%va
for t in [0x5edd64,0x5e23b4,0x5ed978,0x5e23a0]:
    b=t.to_bytes(4,'little'); start=0; rs=[]
    while True:
        i=td.find(b,start)
        if i<0: break
        rs.append(tva+i); start=i+1
    print("=== %08x (%d refs) ==="%(t,len(rs)))
    for va in rs: print("  ",ctx(va))
