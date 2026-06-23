import pefile, capstone
PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH); ib = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b'\x00')==b'.text')
tva = ib + text.VirtualAddress; data = text.get_data()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32); md.detail=True
def dump(a,b,label=""):
    print(f"\n===== {a:08x}..{b:08x} {label} =====")
    off=a-tva
    for ins in md.disasm(data[off:off+(b-a)], a):
        ann=""
        if "0x5bd448" in ins.op_str: ann="  ; screen"
        for g,nm in [(0x5eda4c,"loginPhase"),(0x5eda6c,"srvCount"),(0x5eda38,"autoChar"),
                     (0x5eda68,"prisonTree"),(0x5ec5fe,"selGuard"),(0x5f247d,"acFlag")]:
            if f"0x{g:x}" in ins.op_str: ann+=f"  ; {nm}"
        print(f"  {ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}{ann}")
# rest of LOGINACCEPTED handler incl the screen=0xb write @0x4a6a8c
dump(0x4a6950, 0x4a6ab0, "LOGINACCEPTED tail (screen=0xb @4a6a8c)")
