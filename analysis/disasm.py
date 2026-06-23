import pefile, capstone, sys, re

PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH)
ib = pe.OPTIONAL_HEADER.ImageBase

# map sections
text = None
for s in pe.sections:
    name = s.Name.rstrip(b'\x00').decode(errors='ignore')
    if name == '.text':
        text = s
text_va = ib + text.VirtualAddress
text_data = text.get_data()
text_size = len(text_data)

# Build IAT name->VA(of pointer)
iat = {}  # funcname -> address of the import pointer (where call [addr] points)
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode(errors='ignore')
    for imp in entry.imports:
        if imp.name:
            iat[imp.name.decode()] = imp.address  # already VA (imagebase+thunk RVA)

targets = ['sendto','recvfrom','recv','send','socket','bind','connect','setsockopt','gethostbyname']
print("=== IAT addresses ===")
for t in targets:
    if t in iat: print(f"  {t}: {iat[t]:08x}")

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

# Find all `call dword ptr [imm]` where imm == iat pointer of target
def find_call_sites(ptr_va):
    sites = []
    # pattern: FF 15 <ptr32>
    needle = b'\xff\x15' + ptr_va.to_bytes(4,'little')
    start = 0
    while True:
        i = text_data.find(needle, start)
        if i < 0: break
        sites.append(text_va + i)
        start = i + 1
    return sites

callsites = {}
for t in targets:
    if t in iat:
        cs = find_call_sites(iat[t])
        callsites[t] = cs
        print(f"call [{t}] sites: " + ", ".join(f"{a:08x}" for a in cs))

def va_to_off(va):
    return va - text_va

def disasm_range(va_start, va_end):
    off = va_to_off(va_start)
    n = va_end - va_start
    for ins in md.disasm(text_data[off:off+n], va_start):
        yield ins

def dump_around(va, before=160, after=40, label=""):
    print(f"\n----- around {va:08x} {label} -----")
    start = va - before
    for ins in disasm_range(start, va+after):
        mark = "  <==" if ins.address==va else ""
        print(f"  {ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}{mark}")

# Dump around each sendto and recvfrom site
for t in ['sendto','recvfrom']:
    for site in callsites.get(t, []):
        dump_around(site, before=220, after=30, label=t)
EOF
