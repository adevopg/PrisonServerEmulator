import pefile, capstone, sys, re
PATH = r"C:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
secs=[(base+s.VirtualAddress, base+s.VirtualAddress+max(s.Misc_VirtualSize,s.SizeOfRawData), s.get_data(), s.Name) for s in pe.sections]
def read(va,n):
    for a,b,d,nm in secs:
        if a<=va<b: return d[va-a:va-a+n]
    return b""
def cstr(va,m=200):
    d=read(va,m); z=d.find(b"\x00")
    if z>=0:d=d[:z]
    return d.decode("latin1","replace")
def asciiok(s): return s and len(s)>=3 and all(32<=ord(c)<127 for c in s)
def out(l): sys.stdout.buffer.write((l+"\n").encode("utf-8","replace"))
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32); md.detail=True

def disas(va,n,label):
    out("\n===== %s @ 0x%08x ====="%(label,va))
    for ins in md.disasm(read(va,n),va):
        line="0x%08x  %-7s %s"%(ins.address,ins.mnemonic,ins.op_str)
        for tok in re.split(r"[ ,\[\]]+",ins.op_str):
            if tok.startswith("0x"):
                try:v=int(tok,16)
                except:continue
                if base<=v<base+0x300000:
                    s=cstr(v,160)
                    if asciiok(s): line+='    ; "%s"'%s; break
        out(line)

# Prologo del despachador: como se obtiene el indice desde el opcode.
disas(0x40a2e0, 0x90, "Despachador prologo")

# Buscar en .text el consumidor del evento 0x483 (cmp con 0x483).
out("\n===== Referencias a 0x483 (cmp/push) en .text =====")
for a,b,d,nm in secs:
    if b".text" not in nm and b"CODE" not in nm and not (a<=0x401000<b):
        pass
    # escanear todas las secciones de codigo
    for ins in md.disasm(d, a):
        if ins.mnemonic in ("cmp","sub","add","mov") and "0x483" in ins.op_str:
            out("  %08x  %s %s"%(ins.address,ins.mnemonic,ins.op_str))
    # solo la primera seccion grande de codigo
    if (a<=0x401000<b): break
