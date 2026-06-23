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
        print(f"  {ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}")
# CLASSINFO net case 0x40abd7: how it reads the wire (uncompSize/compSize/zlib) + decompress + call UI 0x4a4620
dump(0x40abd7, 0x40ac90, "net CLASSINFO 0x40abd7 (wire parse + decompress + call 0x4a4620)")
