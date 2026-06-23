import pefile, capstone
PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH); ib = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b'\x00')==b'.text')
tva=ib+text.VirtualAddress; tdata=text.get_data()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32); md.detail=True
CHAR0=0x5e192f
def dump(a,b,label=""):
    print(f"\n===== {a:08x}..{b:08x} {label} =====")
    off=a-tva
    for ins in md.disasm(tdata[off:off+(b-a)], a):
        ann=""
        # detect char-slot base 0x5e192f and offsets
        if "0x5e192f" in ins.op_str: ann+=" ; CHAR0"
        if "0x5e22f8" in ins.op_str: ann+=" ; summary0"
        for g,nm in [(0x5c30a4,"selCharIdx?"),(0x5ec5f4,"selIdx"),(0x5bd448,"screen"),(0x5547d0,"")]:
            if f"0x{g:x}" in ins.op_str: ann+=f" ; {nm}"
        print(f"  {ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}{ann}")
# char-select render funcs (from memory): 0x548700, 0x5482ff, 0x4a87db, 0x4a4a35
dump(0x548700, 0x548820, "char render 0x548700")
dump(0x5482ff, 0x548400, "char render 0x5482ff")
