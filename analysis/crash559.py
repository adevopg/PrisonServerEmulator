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
        mark="  <== FAULT" if ins.address==0x559c4e else ""
        ann=""
        for g,nm in [(0x5ec5d0,"classArr"),(0x5ec5d4,"arr1/attrNames"),(0x5ec5d8,"arr2/skillNames"),
                     (0x5c2b3c,"N0"),(0x5c2b00,"N1"),(0x5c2b28,"N2"),(0x5c30a4,"selClass")]:
            if f"0x{g:x}" in ins.op_str: ann+=f" ; {nm}"
        print(f"  {ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}{mark}{ann}")
dump(0x559bf0, 0x559c80, "crash 0x559c4e (char-create attribute/class array read)")
