import pefile, capstone
PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH); ib = pe.OPTIONAL_HEADER.ImageBase
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
def dis(a,b):
    data=pe.get_data(a-ib,b-a)
    for ins in md.disasm(data,a):
        mk="  <== ret here" if ins.address==0x4a400a else ""
        print("  %08x: %-8s %s%s"%(ins.address,ins.mnemonic,ins.op_str,mk))
print("=== caller around 0x4a400a ===")
dis(0x4a3f60,0x4a4030)
