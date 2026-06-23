import pefile, capstone
PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH); ib = pe.OPTIONAL_HEADER.ImageBase
text=[s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text'][0]
tva=ib+text.VirtualAddress; td=text.get_data()
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
def dis(a,b):
    off=a-tva
    for ins in md.disasm(td[off:off+(b-a)],a):
        print("  %08x: %-8s %s"%(ins.address,ins.mnemonic,ins.op_str))
print("=== receive: reset lastActivity 0x4b4360..0x4b43d0 ===")
dis(0x4b4360,0x4b43d0)
print()
print("=== second timer fn 0x49ef20..0x49ef60 ===")
dis(0x49ef20,0x49ef60)
print()
print("=== elapsed-since-serverparams 0x4b07e0..0x4b0820 ===")
dis(0x4b07e0,0x4b0820)
