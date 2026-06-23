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
        for g,nm in [(0x5eda49,"renderSkip/autoGate"),(0x5eda38,"AutoChar"),(0x5ec5f4,"selIdx"),
                     (0x5ec5fe,"selGuard"),(0x5eda4c,"loginPhase"),(0x5bd448,"screen"),
                     (0x5ee05c,"?A"),(0x5ee066,"?B"),(0x5eda48,"menuBase")]:
            if f"0x{g:x}" in ins.op_str: ann+=f"  ; {nm}"
        print(f"  {ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}{ann}")
# caller 0x549662 of 0x5493d0
dump(0x549600, 0x5496a0, "around 0x549662 (caller of 0x5493d0)")
# function containing push 0x4ae @ 0x54a448
dump(0x54a400, 0x54a470, "around 0x54a448 (push 0x4ae)")
