import pefile, capstone

PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH)
ib = pe.OPTIONAL_HEADER.ImageBase
for s in pe.sections:
    if s.Name.rstrip(b'\x00')==b'.text': text=s
text_va = ib + text.VirtualAddress
data = text.get_data()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32); md.detail=True

# resolve import pointer -> name
iat={}
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in entry.imports:
        if imp.name: iat[imp.address]=imp.name.decode()

def line(ins):
    extra=""
    # annotate call dword ptr [imm] with import name
    if ins.mnemonic=='call' and ins.op_str.startswith('dword ptr ['):
        try:
            addr=int(ins.op_str.split('[')[1].split(']')[0],16)
            if addr in iat: extra="   ; "+iat[addr]
        except: pass
    return f"  {ins.address:08x}: {ins.mnemonic:7s} {ins.op_str}{extra}"

def dump(va, maxlen=700, label=""):
    print(f"\n===== {label} @ {va:08x} =====")
    off=va-text_va
    for ins in md.disasm(data[off:off+maxlen], va):
        print(line(ins))
        if ins.mnemonic=='ret': break

# Find direct callers (E8 rel32) of a function
def callers(func_va):
    res=[]
    for i in range(len(data)-5):
        if data[i]==0xe8:
            rel=int.from_bytes(data[i+1:i+5],'little',signed=True)
            tgt=text_va+i+5+rel
            if tgt==func_va: res.append(text_va+i)
    return res

# full send_builder
dump(0x412370, 900, "send_builder")
# helper that produces value stored at +0xc (timestamp/seq?)
dump(0x415a80, 200, "tick_or_seq(415a80)")
# helper before enqueue
dump(0x411b50, 200, "helper_411b50")
# the generic low-level sender (sockaddr family=2)
print("\n### callers of low-level send 0x411c50:", [hex(a) for a in callers(0x411c50)])
print("### callers of send_builder 0x412370:", [hex(a) for a in callers(0x412370)])
