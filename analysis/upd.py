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
        for g,nm in [(0x5be628,"updFlag"),(0x5be62c,"acctPtr"),(0x5eda4c,"loginPhase"),
                     (0x5bd448,"screen"),(0x5be639,"?"),(0x5be640,"?")]:
            if f"0x{g:x}" in ins.op_str: ann+=f"  ; {nm}"
        tgt=""
        if ins.mnemonic.startswith('j') or ins.mnemonic=='call':
            tgt=""
        # flag pushes (event ids)
        print(f"  {ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}{ann}")
# 0x13d5 / update-manifest / LOGINACCEPTED handler 0x40b7bb
dump(0x40b7bb, 0x40b8e0, "net 0x13d5 handler 0x40b7bb (count + updFlag -> LOGINACCEPTED)")
# the LOGINACCEPTED fire site 0x40c50c referenced in memory
dump(0x40c4e0, 0x40c560, "0x40c50c LOGINACCEPTED fire (updFlag gate)")
