import pefile, capstone
PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH); ib = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b'\x00')==b'.text')
tva=ib+text.VirtualAddress; tdata=text.get_data()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32); md.detail=True
G=0x5e1980
needle=G.to_bytes(4,'little')
hits=[]; start=0
while True:
    i=tdata.find(needle,start)
    if i<0: break
    hits.append(tva+i); start=i+1
print(f"refs to 0x{G:x}:")
for h in hits:
    for back in range(2,10):
        off=(h-back)-tva
        try: ins=next(md.disasm(tdata[off:off+14], h-back))
        except StopIteration: continue
        if ins.address+ins.size>h and f"0x{G:x}" in ins.op_str:
            w = ins.mnemonic=="mov" and ins.op_str.strip().startswith(f"dword ptr [0x{G:x}]")
            print(f"  {ins.address:08x}: {ins.mnemonic:6s} {ins.op_str}   [{'WRITE' if w else 'read'}]")
            break
# char-slot-0 working copy base is 0x5e192f; show offset
print(f"\n0x{G:x} - 0x5e192f = +0x{G-0x5e192f:x} (offset within char slot 0, if in copy region 0x342)")
# also: relation to the LOGINACCEPTED account header globals
for g,nm in [(0x5e1928,"accountId glob"),(0x5e192f,"charSlot0 base"),(0x5e22f8,"summary0")]:
    print(f"  0x{g:x} {nm}")
