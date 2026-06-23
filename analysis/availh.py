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
        for g,nm in [(0x5be628,"updFlag"),(0x5eda4c,"loginPhase"),(0x5bd448,"screen"),
                     (0x5be62c,"acctPtr"),(0x5eda68,"prisonTree")]:
            if f"0x{g:x}" in ins.op_str: ann+=f"  ; {nm}"
        # mark push of small ints (event ids)
        print(f"  {ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}{ann}")
dump(0x40aa56, 0x40ab10, "net AVAILABLESERVERS 0x40aa56 (wire 0x13ac)")
dump(0x40aaa4, 0x40ab60, "net SERVERADDED 0x40aaa4 (wire 0x13a9) [overlaps]")
