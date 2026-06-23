import pefile, capstone
PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH); ib = pe.OPTIONAL_HEADER.ImageBase
text=[s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text'][0]
tva=ib+text.VirtualAddress; td=text.get_data()
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
def ctx(va):
    off=va-tva-6
    for ins in md.disasm(td[off:off+14], tva+off):
        if ins.address<=va<=ins.address+ins.size:
            return "%08x: %-8s %s"%(ins.address,ins.mnemonic,ins.op_str)
    return "%08x ?"%va
# refs to ping value [0x5edd60] and ELAPSED [0x5e23b4]
for t in [0x5edd60,0x5e23b4]:
    b=t.to_bytes(4,'little'); s=[];i=0
    while True:
        i=td.find(b,i)
        if i<0:break
        s.append(tva+i);i+=1
    print("=== %08x (%d refs) ==="%(t,len(s)))
    for va in s: print("   ",ctx(va))
# find "..." strings and "Ping" strings in rdata
rd=[x for x in pe.sections if x.Name.rstrip(b'\0')==b'.rdata'][0]
rva=ib+rd.VirtualAddress; rdd=rd.get_data()
for needle in [b'...', b'Ping', b'PING', b'ping', b'%d ms', b' ms']:
    i=rdd.find(needle)
    while i>=0 and i<len(rdd):
        # context string
        st=i
        while st>0 and 32<=rdd[st-1]<127: st-=1
        en=rdd.find(b'\0',i)
        s=rdd[st:en].decode('latin1','replace')
        if len(s)<40:
            print("STR @%08x: %r"%(rva+st, s))
        i=rdd.find(needle,i+1)
        if rdd.find(needle,i)<0 or i> len(rdd): break
