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
        if "0x5e192f" in ins.op_str: ann+=" ; CHAR0"
        for g,nm in [(0x5ec5d0,"classArr"),(0x5ec5f4,"selIdx"),(0x5eda68,"prisonTree")]:
            if f"0x{g:x}" in ins.op_str: ann+=f" ; {nm}"
        # highlight ebx+offset reads (char fields) and calls
        print(f"  {ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}{ann}")
dump(0x5481d0, 0x548300, "char render entry 0x5481d0 (appearance/model setup)")
