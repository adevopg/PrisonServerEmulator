import pefile, capstone, struct
PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH); ib = pe.OPTIONAL_HEADER.ImageBase
text=[s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text'][0]
tva=ib+text.VirtualAddress; td=text.get_data()
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
def dis(a,b):
    off=a-tva
    for ins in md.disasm(td[off:off+(b-a)],a):
        print("  %08x: %-8s %s"%(ins.address,ins.mnemonic,ins.op_str))
print("=== dispatcher head 0x4b4310..0x4b4400 ===")
dis(0x4b4310,0x4b4400)
print()
print("=== full PONG handler 0x4b439b..0x4b4430 ===")
dis(0x4b439b,0x4b4430)
