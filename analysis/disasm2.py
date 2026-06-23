import pefile, capstone

PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH)
ib = pe.OPTIONAL_HEADER.ImageBase
for s in pe.sections:
    if s.Name.rstrip(b'\x00')==b'.text':
        text=s
text_va = ib + text.VirtualAddress
data = text.get_data()
end_va = text_va + len(data)

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32); md.detail=True

def func_start(va):
    # walk backwards to find 'push ebp; mov ebp,esp' or after int3 padding
    off = va - text_va
    # search backward for 0x55 8B EC (push ebp; mov ebp,esp)
    for i in range(off, max(0,off-2000), -1):
        if data[i]==0x55 and data[i+1]==0x8b and data[i+2]==0xec:
            return text_va + i
    return va-200

def dump_func(va, maxlen=900, label=""):
    start = func_start(va)
    print(f"\n========== function @ {start:08x} (target {va:08x}) {label} ==========")
    off = start - text_va
    cnt=0
    for ins in md.disasm(data[off:off+maxlen], start):
        mark = "   <==TARGET" if ins.address==va else ""
        print(f"  {ins.address:08x}: {ins.mnemonic:7s} {ins.op_str}{mark}")
        cnt+=1
        # stop on ret followed by int3 padding (end of function) after target
        if ins.mnemonic=='ret' and ins.address>va:
            break
    return start

import sys
targets = {
  'recvfrom_handler': 0x4128fa,
  'send_builder':     0x412542,
}
for name,va in targets.items():
    dump_func(va, maxlen=1200, label=name)
