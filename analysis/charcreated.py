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
        # flag event-id pushes
        if ins.mnemonic=="push" and ins.op_str.startswith("0x48"): ann=" <== EVENT"
        print(f"  {ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}{ann}")
dump(0x40a4da, 0x40a570, "net char handlers 0x40a4da/0x40a54f/0x40a567 (find event 0x484)")
