import pefile, capstone
PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH); ib = pe.OPTIONAL_HEADER.ImageBase
text=[s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text'][0]
tva=ib+text.VirtualAddress; td=text.get_data()
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
def dis(a,b):
    off=a-tva
    for ins in md.disasm(td[off:off+(b-a)],a):
        mk="  <== CRASH" if ins.address==0x42242c else ""
        print("  %08x: %-8s %s%s"%(ins.address,ins.mnemonic,ins.op_str,mk))
print("=== around crash 0x42242c ===")
dis(0x4223e0,0x422460)
