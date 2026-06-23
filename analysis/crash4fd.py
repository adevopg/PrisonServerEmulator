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
        mark="  <== FAULT" if ins.address==0x4fd3ff else ""
        ann=""
        for g,nm in [(0x5e192f,"charSlot0"),(0x5e22f8,"charSummary0"),(0x5bd448,"screen"),
                     (0x5eda4c,"loginPhase"),(0x5e1928,"acctId")]:
            if f"0x{g:x}" in ins.op_str: ann+=f" ; {nm}"
        print(f"  {ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}{mark}{ann}")
dump(0x4fd380, 0x4fd440, "crash @0x4fd3ff (char-list render?)")
