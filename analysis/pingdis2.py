import pefile, capstone
PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH); ib = pe.OPTIONAL_HEADER.ImageBase
text=[s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text'][0]
tva=ib+text.VirtualAddress; td=text.get_data()
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32); md.detail=True
def dis(a,b):
    off=a-tva
    for ins in md.disasm(td[off:off+(b-a)],a):
        print("  %08x: %-8s %s"%(ins.address,ins.mnemonic,ins.op_str))
print("=== entry to printf-handler 0x4b4e60..0x4b4f08 ===")
dis(0x4b4e60,0x4b4f08)
# read the two format strings
data=[s for s in pe.sections if s.Name.rstrip(b'\0')==b'.rdata'][0]
dva=ib+data.VirtualAddress; dd=data.get_data()
def rs(va):
    o=va-dva
    if o<0 or o>len(dd): 
        # maybe in .data
        return "<not rdata>"
    e=dd.find(b'\0',o); return dd[o:e].decode('latin1','replace')
print("fmt 0x5a74e0:", repr(rs(0x5a74e0)))
print("fmt 0x5a7554:", repr(rs(0x5a7554)))
