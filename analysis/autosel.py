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
        for g,nm in [(0x5eda38,"AutoChar"),(0x5f247d,"acGuard"),(0x5ec5fe,"selGuard"),
                     (0x5ec5f4,"selIdxStore"),(0x5eda3c,"AutoLogin?"),(0x5eda4c,"loginPhase")]:
            if f"0x{g:x}" in ins.op_str: ann+=f"  ; {nm}"
        print(f"  {ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}{ann}")
dump(0x549500, 0x5495f0, "per-frame auto-select check 0x549500")
