import pefile, capstone
PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH); ib = pe.OPTIONAL_HEADER.ImageBase
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32); md.detail=True
def rva_data(va, n):
    return pe.get_data(va-ib, n)
def sec_of(va):
    for s in pe.sections:
        a=ib+s.VirtualAddress
        if a<=va<a+s.Misc_VirtualSize: return s
    return None
text = next(s for s in pe.sections if s.Name.rstrip(b'\x00')==b'.text')
tva=ib+text.VirtualAddress; tdata=text.get_data()
def dump(a,b,label=""):
    print(f"\n===== {a:08x}..{b:08x} {label} =====")
    off=a-tva
    for ins in md.disasm(tdata[off:off+(b-a)], a):
        print(f"  {ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}")
# the recv dispatcher: see how it indexes the jump table
dump(0x40a317, 0x40a3a0, "recv dispatch 0x40a317")
