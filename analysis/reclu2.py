import pefile, capstone

PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH)
ib = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b'\x00')==b'.text')
text_va = ib + text.VirtualAddress
data = text.get_data()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

def find_imm_refs(imm):
    """find all .text bytes containing the little-endian dword imm"""
    needle = imm.to_bytes(4,'little')
    hits=[]; start=0
    while True:
        i = data.find(needle, start)
        if i<0: break
        hits.append(text_va+i); start=i+1
    return hits

# All references to recluCounter 0x5eda78 — classify read vs write by disassembling
# a few bytes before each hit.
print("=== refs to 0x5eda78 (recluCounter) ===")
for h in find_imm_refs(0x5eda78):
    # disassemble the instruction that ends with this imm: back up to 8 bytes
    for back in range(2,9):
        off = (h-back)-text_va
        try:
            ins = next(md.disasm(data[off:off+12], h-back))
        except StopIteration:
            continue
        if ins.address+ins.size > h and f"0x5eda78" in ins.op_str:
            kind = "WRITE" if ins.mnemonic=="mov" and ins.op_str.strip().startswith("dword ptr [0x5eda78]") else "read?"
            print(f"  {ins.address:08x}: {ins.mnemonic} {ins.op_str}   [{kind}]")
            break

# disasm around the other writer 0x592429
def dump(a,b,label=""):
    print(f"\n===== {a:08x}..{b:08x} {label} =====")
    off=a-text_va
    for ins in md.disasm(data[off:off+(b-a)], a):
        ann=""
        for g,nm in [(0x5eda78,"recluCounter"),(0x5eda70,"srvDataArr"),(0x5eda74,"selIdx"),(0x5eda6c,"srvCount")]:
            if f"0x{g:x}" in ins.op_str: ann+=f"  ; {nm}"
        print(f"  {ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}{ann}")

dump(0x5923c0, 0x592470, "other recluCounter writer area (0x592429)")
