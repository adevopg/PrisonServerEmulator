import pefile, capstone
PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH); ib = pe.OPTIONAL_HEADER.ImageBase
text=[s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text'][0]
tva=ib+text.VirtualAddress; td=text.get_data()
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
rd=[x for x in pe.sections if x.Name.rstrip(b'\0')==b'.rdata'][0]
rva=ib+rd.VirtualAddress; rdd=rd.get_data()
def rs(va):
    o=va-rva
    if o<0 or o>=len(rdd): return None
    e=rdd.find(b'\0',o); s=rdd[o:e]
    try: return s.decode('latin1')
    except: return None
def dis(a,b):
    off=a-tva
    for ins in md.disasm(td[off:off+(b-a)],a):
        ann=""
        for tok in ins.op_str.replace(',',' ').split():
            if tok.startswith('0x59') or tok.startswith('0x5a') or tok.startswith('0x5b'):
                try:
                    v=int(tok,16); st=rs(v)
                    if st is not None and 1<=len(st)<40: ann+='  ; "%s"'%st
                except: pass
        print("  %08x: %-8s %s%s"%(ins.address,ins.mnemonic,ins.op_str,ann))
print("=== 0x50ae60..0x50af20 (cmp state,3) ===")
dis(0x50ae60,0x50af20)
