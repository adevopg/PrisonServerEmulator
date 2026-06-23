import pefile, capstone
PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH); ib = pe.OPTIONAL_HEADER.ImageBase
text=[s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text'][0]
tva=ib+text.VirtualAddress; td=text.get_data()
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
secs=[(ib+s.VirtualAddress, ib+s.VirtualAddress+len(s.get_data()), s.get_data(), ib+s.VirtualAddress) for s in pe.sections]
def rs(va):
    for a,b,d,base in secs:
        if a<=va<b:
            o=va-base; e=d.find(b'\0',o)
            if e<0 or e-o>60: return None
            try: return d[o:e].decode('latin1')
            except: return None
    return None
def dis(a,b):
    off=a-tva
    for ins in md.disasm(td[off:off+(b-a)],a):
        ann=""
        for tok in ins.op_str.replace(',',' ').replace('[',' ').replace(']',' ').split():
            if tok.startswith('0x5'):
                try:
                    v=int(tok,16); st=rs(v)
                    if st and any(32<=ord(c)<127 for c in st) and len(st)>=1 and len(st)<40:
                        ann+='  ; "%s"'%st
                except: pass
        print("  %08x: %-7s %s%s"%(ins.address,ins.mnemonic,ins.op_str,ann))
print("=== connection/ping draw 0x49e960..0x49eb00 (after the color logic) ===")
dis(0x49e960,0x49eb00)
