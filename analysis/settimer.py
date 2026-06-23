import pefile, capstone, struct
PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH); ib = pe.OPTIONAL_HEADER.ImageBase
text=[s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text'][0]
tva=ib+text.VirtualAddress; td=text.get_data()
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
iat={}
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in entry.imports:
        if imp.name: iat[imp.name.decode()]=imp.address
for fn in ['SetTimer','timeSetEvent','timeGetTime','GetTickCount','KillTimer']:
    if fn in iat: print("%s @ %08x"%(fn,iat[fn]))
def sites(ptr):
    n=b'\xff\x15'+ptr.to_bytes(4,'little'); s=[];i=0
    while True:
        i=td.find(n,i)
        if i<0:break
        s.append(tva+i);i+=1
    return s
for fn in ['SetTimer']:
    if fn not in iat: continue
    for va in sites(iat[fn]):
        print("\n--- SetTimer call @ %08x ---"%va)
        off=va-tva-40
        for ins in md.disasm(td[off:off+46], tva+off):
            if ins.address<=va: print("  %08x: %-8s %s"%(ins.address,ins.mnemonic,ins.op_str))
