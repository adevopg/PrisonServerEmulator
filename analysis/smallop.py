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
print("=== F handler head 0x40fb60..0x40fbe0 ===")
dis(0x40fb60,0x40fbe0)
print()
print("=== PONG-send context 0x40fee0..0x40ff60 ===")
dis(0x40fee0,0x40ff60)
print()
print("=== ping-tick send context (0x422) 0x410300..0x410340 ===")
dis(0x410300,0x410340)
