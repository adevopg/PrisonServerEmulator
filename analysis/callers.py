import pefile, capstone
PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH); ib = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b'\x00')==b'.text')
tva=ib+text.VirtualAddress; tdata=text.get_data()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

def callers_of(target):
    """find E8 rel32 calls to target"""
    hits=[]
    for i in range(len(tdata)-5):
        if tdata[i]==0xE8:
            rel=int.from_bytes(tdata[i+1:i+5],'little',signed=True)
            dst=(tva+i+5+rel)&0xffffffff
            if dst==target: hits.append(tva+i)
    return hits

for fn,nm in [(0x5493d0,"0x5493d0 (sends net 0x139f)"),(0x548750,"0x548750 (pre-select)")]:
    cs=callers_of(fn)
    print(f"callers of {nm}: {[hex(x) for x in cs]}")

# also: find pushes of cmd 0x4ae (the select cmd id) -> 68 ae 04 00 00
needle=b'\x68\xae\x04\x00\x00'
hits=[]; start=0
while True:
    i=tdata.find(needle,start)
    if i<0: break
    hits.append(tva+i); start=i+1
print("push 0x4ae sites:", [hex(x) for x in hits])

# disasm a small window around each push 0x4ae to see the sender context
for site in hits:
    print(f"\n--- around push 0x4ae @ {site:08x} ---")
    off=site-tva-40
    for ins in md.disasm(tdata[off:off+70], site-40):
        mark="  <==" if ins.address==site else ""
        print(f"  {ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}{mark}")
