import pefile, capstone
PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH); ib = pe.OPTIONAL_HEADER.ImageBase
text=[s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text'][0]
tva=ib+text.VirtualAddress; td=text.get_data()
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
# search for push 0x423 (68 23 04 00 00) and cmp/mov with 0x423, and 0x422
for needle,desc in [(b'\x68\x23\x04\x00\x00','push 0x423'),(b'\x68\x22\x04\x00\x00','push 0x422'),
                    (b'\x3d\x23\x04\x00\x00','cmp eax,0x423')]:
    start=0
    while True:
        i=td.find(needle,start)
        if i<0: break
        va=tva+i
        # context
        off=i-24
        out=[]
        for ins in md.disasm(td[off:off+48], tva+off):
            if ins.address> va+5: break
            out.append("    %08x: %-7s %s"%(ins.address,ins.mnemonic,ins.op_str))
        print("%s @ %08x"%(desc,va))
        print("\n".join(out[-6:]))
        print()
        start=i+1
