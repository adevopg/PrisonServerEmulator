import pefile, capstone
PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH); ib = pe.OPTIONAL_HEADER.ImageBase
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
data=pe.sections; 
def rs(va):
    try:
        d=pe.get_data(va-ib,200); e=d.find(b'\0'); 
        return d[:e].decode('latin1','replace')
    except: return "?"
def dis(a,b,marks=()):
    d=pe.get_data(a-ib,b-a)
    for ins in md.disasm(d,a):
        mk=""
        for m in marks:
            if ins.address==m: mk="  <== ret"
        s=ins.op_str
        # annotate string pushes
        if ins.mnemonic=='push' and ins.op_str.startswith('0x59') or ins.op_str.startswith('0x5a') or ins.op_str.startswith('0x5b'):
            try:
                v=int(ins.op_str,16); st=rs(v)
                if st and all(32<=ord(c)<127 or c in '\n\t' for c in st[:1]): mk+="   ; \"%s\""%st[:40]
            except: pass
        print("  %08x: %-8s %s%s"%(ins.address,ins.mnemonic,s,mk))
print("=== caller 0x547810..0x547870 (ret 0x54785e) ===")
dis(0x547810,0x547870,(0x54785e,))
print()
print("=== 0x4a6150..0x4a6195 (ret 0x4a618d) ===")
dis(0x4a6150,0x4a6195,(0x4a618d,))
