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
        for g,nm in [(0x5eda78,"recluCounter"),(0x5eda70,"srvDataArr"),(0x5eda74,"selIdx"),
                     (0x5eda68,"prisonTree"),(0x5ec5d0,"classArr"),(0x5c30a4,"selClassIdx")]:
            if f"0x{g:x}" in ins.op_str: ann+=f" ; {nm}"
        print(f"  {ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}{ann}")
dump(0x4555a0, 0x455600, "caller 0x4555ec -> malloc (size?)")
dump(0x5974a0, 0x5974e0, "0x5974cd")
dump(0x455400, 0x455440, "0x45542f")
