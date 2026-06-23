import pefile, capstone
PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH); ib = pe.OPTIONAL_HEADER.ImageBase
print("ImageBase %08x"%ib)
for s in pe.sections:
    nm=s.Name.rstrip(b'\0').decode('latin1')
    print("  %-8s va=%08x..%08x rawsz=%x"%(nm, ib+s.VirtualAddress, ib+s.VirtualAddress+s.Misc_VirtualSize, s.SizeOfRawData))
# disasm using get_data by RVA
target=0x42242c
start=target-0x40
data=pe.get_data(start-ib, 0xa0)
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
for ins in md.disasm(data,start):
    mk="  <== CRASH" if ins.address==target else ""
    print("  %08x: %-8s %s%s"%(ins.address,ins.mnemonic,ins.op_str,mk))
