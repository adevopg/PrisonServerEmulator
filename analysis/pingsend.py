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
for name,a,b in [("0x49e8a0 (ELAPSED>5s action)",0x49e8a0,0x49e960),
                 ("0x49ec30",0x49ec30,0x49eca0),
                 ("0x49eca0",0x49eca0,0x49ed40),
                 ("0x411b50 (now-ms)",0x411b50,0x411b80)]:
    print("=== %s ==="%name); dis(a,b); print()
