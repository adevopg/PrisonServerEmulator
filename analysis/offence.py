import pefile, capstone
PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH); ib = pe.OPTIONAL_HEADER.ImageBase
# locate the error string VA
data_all=open(PATH,'rb').read()
fo=data_all.find(b"OffenceList is empty after")
# map file offset -> VA
va=None
for s in pe.sections:
    if s.PointerToRawData<=fo<s.PointerToRawData+s.SizeOfRawData:
        va=ib+s.VirtualAddress+(fo-s.PointerToRawData); break
print("error string file 0x%x -> VA 0x%x"%(fo,va))
# also the "LeechClassInfoPacket" string VA
fo2=data_all.find(b"LeechClassInfoPacket\x00")
va2=None
for s in pe.sections:
    if s.PointerToRawData<=fo2<s.PointerToRawData+s.SizeOfRawData:
        va2=ib+s.VirtualAddress+(fo2-s.PointerToRawData); break
print("LeechClassInfoPacket string VA 0x%x"%va2)

text = next(s for s in pe.sections if s.Name.rstrip(b'\x00')==b'.text')
tva=ib+text.VirtualAddress; tdata=text.get_data()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32); md.detail=True
# find push of the error string VA (68 <va>)
for tgt,nm in [(va,"OffenceList-err"),(va2,"LeechClassInfoPacket")]:
    needle=b'\x68'+tgt.to_bytes(4,'little')
    i=tdata.find(needle)
    while i>=0:
        site=tva+i
        print(f"\n--- push {nm} @ {site:08x} ---")
        off=site-tva-90
        for ins in md.disasm(tdata[off:off+110], site-90):
            mark="  <==" if ins.address==site else ""
            ann=""
            for g,gn in [(0x5ec5d0,"classArr"),(0x5ec5d4,"arr1/N1"),(0x5ec5d8,"arr2/N2"),
                         (0x5c2b3c,"N0"),(0x5c2b00,"N1cnt"),(0x5c2b28,"N2cnt")]:
                if f"0x{g:x}" in ins.op_str: ann+=f" ; {gn}"
            print(f"  {ins.address:08x}: {ins.mnemonic:7s} {ins.op_str}{mark}{ann}")
        i=tdata.find(needle,i+1)
