import pefile, capstone, struct
PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH); ib = pe.OPTIONAL_HEADER.ImageBase
text=[s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text'][0]
tva=ib+text.VirtualAddress; td=text.get_data()
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
# find all instructions referencing target immediates
targets=[0x5bd680,0x5bd684,0x5bd688,0x5ed960,0x59a098,0x5bd900]
tb={t:t.to_bytes(4,'little') for t in targets}
hits={t:[] for t in targets}
for t,b in tb.items():
    start=0
    while True:
        i=td.find(b,start)
        if i<0: break
        hits[t].append(tva+i)
        start=i+1
for t in targets:
    print("=== refs to %08x (%d) ==="%(t,len(hits[t])))
    for va in hits[t][:30]:
        # disasm a couple instrs around to get context: back up 8 bytes and decode forward to va+6
        off=va-tva-8
        for ins in md.disasm(td[off:off+20], tva+ (off)):
            if ins.address<=va<=ins.address+ins.size:
                print("   %08x: %-8s %s"%(ins.address,ins.mnemonic,ins.op_str))
                break
