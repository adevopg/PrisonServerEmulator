import pefile, capstone
PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH); ib = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b'\x00')==b'.text')
tva=ib+text.VirtualAddress; tdata=text.get_data()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32); md.detail=True

# all writes to updFlag 0x5be628
needle=(0x5be628).to_bytes(4,'little')
hits=[]; start=0
while True:
    i=tdata.find(needle,start)
    if i<0: break
    hits.append(tva+i); start=i+1
print("refs to updFlag 0x5be628:")
for h in hits:
    for back in range(2,11):
        off=(h-back)-tva
        try: ins=next(md.disasm(tdata[off:off+15], h-back))
        except StopIteration: continue
        if ins.address+ins.size>h and "0x5be628" in ins.op_str:
            w = ins.mnemonic=="mov" and "[0x5be628]" in ins.op_str.split(',')[0]
            print(f"  {ins.address:08x}: {ins.mnemonic:6s} {ins.op_str}  [{'WRITE' if w else 'read'}]")
            break

def dump(a,b,label=""):
    print(f"\n===== {a:08x}..{b:08x} {label} =====")
    off=a-tva
    for ins in md.disasm(tdata[off:off+(b-a)], a):
        ann=""
        for g,nm in [(0x5be628,"updFlag"),(0x5be62c,"acctPtr"),(0x5be624,"?")]:
            if f"0x{g:x}" in ins.op_str: ann+=f"  ; {nm}"
        print(f"  {ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}{ann}")
dump(0x409900, 0x4099b0, "around updFlag setter 0x409958")
