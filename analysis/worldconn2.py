import pefile, capstone
PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH); ib = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b'\x00')==b'.text')
tva=ib+text.VirtualAddress; tdata=text.get_data()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32); md.detail=True
# find call sites of gethostbyname (FF 15 60 a3 59 00) and connect (FF 15 3c a3 59 00)
def callsites(ptr):
    needle=b'\xff\x15'+ptr.to_bytes(4,'little'); hits=[]; i=0
    while True:
        i=tdata.find(needle,i)
        if i<0: break
        hits.append(tva+i); i+=1
    return hits
print("gethostbyname call sites:", [hex(x) for x in callsites(0x59a360)])
print("connect call sites:", [hex(x) for x in callsites(0x59a33c)])
print("htons call sites:", [hex(x) for x in callsites(0x59a364)])
def dump(a,b,label=""):
    print(f"\n===== {a:08x}..{b:08x} {label} =====")
    off=a-tva
    for ins in md.disasm(tdata[off:off+(b-a)], a):
        ann=""
        if "0x5b9f00" in ins.op_str or "0x5b9f04" in ins.op_str: ann=" ; 'prisonserver.com'"
        if "0x61a9" in ins.op_str: ann=" ; 25001"
        for n,p in [("gethostbyname",0x59a360),("connect",0x59a33c),("htons",0x59a364),("inet_addr",0x59a35c)]:
            if f"0x{p:x}" in ins.op_str: ann+=f" ; {n}"
        print(f"  {ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}{ann}")
# dump around first gethostbyname + htons(25001) sites
for site in callsites(0x59a360)[:2]:
    dump(site-0x60, site+0x20, "gethostbyname caller")
