import pefile, capstone
PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH); ib = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b'\x00')==b'.text')
tva=ib+text.VirtualAddress; tdata=text.get_data()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32); md.detail=True
def dump(a,b,label=""):
    print(f"\n===== {a:08x}..{b:08x} {label} =====")
    off=a-tva
    for ins in md.disasm(tdata[off:off+(b-a)], a):
        print(f"  {ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}")
# dispatcher entry + setup of eax(->ebx) and [ebp-0x2108](->esi)
dump(0x40a280, 0x40a360, "dispatcher setup (eax/ebx/esi)")
