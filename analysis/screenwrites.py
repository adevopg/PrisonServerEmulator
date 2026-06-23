import pefile, capstone

PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH)
ib = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b'\x00')==b'.text')
text_va = ib + text.VirtualAddress
data = text.get_data()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

SCREEN=0x5bd448
def find(imm):
    needle=imm.to_bytes(4,'little'); hits=[]; start=0
    while True:
        i=data.find(needle,start)
        if i<0: break
        hits.append(text_va+i); start=i+1
    return hits

print("=== writes/refs to screen var 0x5bd448 ===")
for h in find(SCREEN):
    for back in range(2,10):
        off=(h-back)-text_va
        try: ins=next(md.disasm(data[off:off+14], h-back))
        except StopIteration: continue
        if ins.address+ins.size>h and f"0x{SCREEN:x}" in ins.op_str:
            w = ins.op_str.strip().startswith(f"dword ptr [0x{SCREEN:x}]") and ins.mnemonic in("mov","and","or")
            tag="WRITE" if w else "ref"
            print(f"  {ins.address:08x}: {ins.mnemonic:6s} {ins.op_str}   [{tag}]")
            break

def dump(a,b,label=""):
    print(f"\n===== {a:08x}..{b:08x} {label} =====")
    off=a-text_va
    for ins in md.disasm(data[off:off+(b-a)], a):
        ann=""
        if f"0x{SCREEN:x}" in ins.op_str: ann="  ; screen"
        for g,nm in [(0x5eda4c,"loginPhase"),(0x5eda6c,"srvCount"),(0x5eda38,"autoChar"),(0x5eda68,"prisonTree")]:
            if f"0x{g:x}" in ins.op_str: ann+=f"  ; {nm}"
        print(f"  {ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}{ann}")

# LOGINACCEPTED UI handler and AVAILABLESERVERS UI handler
dump(0x4a68a2, 0x4a6960, "LOGINACCEPTED UI 0x4a68a2")
dump(0x4a7022, 0x4a70f0, "AVAILABLESERVERS UI 0x4a7022")
