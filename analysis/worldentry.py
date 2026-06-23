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
        ann=""
        if ins.mnemonic=="push" and re._compile if False else (ins.mnemonic=="push" and ins.op_str.startswith("0x4") and len(ins.op_str)==5): ann=" <ev?"
        print(f"  {ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}{ann}")
import re
# 0x138e received handler, and neighbors (world login/enter responses)
dump(0x40add4, 0x40af80, "world handlers 0x40add4(0x138d)/0x40af0b(0x138e)")
