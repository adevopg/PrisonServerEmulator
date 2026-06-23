# (1) Encuentra el opcode de red de cada caso del switch del despachador (0x40a317)
# (2) Encuentra el consumidor del evento local 0x483 y los strings de rechazo.
import pefile, capstone, sys

PATH = r"C:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
secs = [(base+s.VirtualAddress, base+s.VirtualAddress+max(s.Misc_VirtualSize,s.SizeOfRawData), s.get_data()) for s in pe.sections]
def read(va,n):
    for a,b,d in secs:
        if a<=va<b: return d[va-a:va-a+n]
    return b""
def u32(va):
    d=read(va,4); return int.from_bytes(d,"little") if len(d)==4 else 0
def cstr(va,m=200):
    d=read(va,m); z=d.find(b"\x00")
    if z>=0:d=d[:z]
    return d.decode("latin1","replace")
def asciiok(s): return s and len(s)>=3 and all(32<=ord(c)<127 for c in s)
def out(l): sys.stdout.buffer.write((l+"\n").encode("utf-8","replace"))

md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32); md.detail=True

# --- (1) Buscar la tabla de saltos del despachador de mensajes de red ---
out("===== Despachador 0x40a317: buscar jump table =====")
code=read(0x40a317,0x300)
tbl=None; subv=None
for ins in md.disasm(code,0x40a317):
    if ins.mnemonic=="sub" and "eax" in ins.op_str:
        out("  %08x %s %s"%(ins.address,ins.mnemonic,ins.op_str))
    if ins.mnemonic=="cmp":
        out("  %08x %s %s"%(ins.address,ins.mnemonic,ins.op_str))
    if ins.mnemonic=="jmp" and "[" in ins.op_str and "*4" in ins.op_str:
        out("  %08x JMP TABLE %s"%(ins.address,ins.op_str))
        # extraer la direccion base de la tabla
        import re
        m=re.search(r"\+ (0x[0-9a-f]+)\]",ins.op_str)
        if not m: m=re.search(r"(0x[0-9a-f]+)\]",ins.op_str)
        if m: tbl=int(m.group(1),16)
        break

if tbl:
    out("\nTabla de saltos en 0x%08x:"%tbl)
    for i in range(0,80):
        t=u32(tbl+i*4)
        if not (base<=t<base+0x300000): break
        mark=""
        if t==0x40a9a4: mark="  <<< LOGINREJECTED (evento 0x483)"
        out("  idx %2d -> 0x%08x%s"%(i,t,mark))

# --- (2) Strings del subsistema de login (alrededor de SomeraLoginSystem.cpp) ---
out("\n===== Strings legibles 0x599000..0x5a4000 (zona login) =====")
va=0x599000
end=0x5a4000
while va<end:
    s=cstr(va,200)
    if asciiok(s):
        out("  0x%08x  %s"%(va,s))
        va+=len(s)+1
    else:
        va+=1
