# Desensambla los manejadores de login para sacar los codigos de estado/rechazo.
import pefile, capstone, sys

PATH = r"C:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
print("ImageBase=0x%08x" % base)

# Mapear datos de las secciones para leer bytes por VA.
secs = []
for s in pe.sections:
    secs.append((base + s.VirtualAddress,
                 base + s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData),
                 s.get_data()))

def read(va, n):
    for a,b,data in secs:
        if a <= va < b:
            off = va - a
            return data[off:off+n]
    return b""

def cstr(va, maxn=200):
    d = read(va, maxn)
    z = d.find(b"\x00")
    if z >= 0: d = d[:z]
    try: return d.decode("latin1")
    except: return repr(d)

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

def asciiok(s):
    return s and len(s) >= 3 and all(32 <= ord(c) < 127 for c in s)

def out(line):
    sys.stdout.buffer.write((line + "\n").encode("utf-8", "replace"))

def disas(va, n, label):
    out("\n===== %s @ 0x%08x =====" % (label, va))
    code = read(va, n)
    for ins in md.disasm(code, va):
        line = "0x%08x  %-7s %s" % (ins.address, ins.mnemonic, ins.op_str)
        for tok in ins.op_str.replace(",", " ").replace("[", " ").replace("]", " ").split():
            if tok.startswith("0x"):
                try: v = int(tok, 16)
                except: continue
                if base <= v < base + 0x300000:
                    s = cstr(v, 160)
                    if asciiok(s):
                        line += '    ; "%s"' % s
                        break
        out(line)

disas(0x40a9a4, 700, "LOGINREJECTED handler 0x40a9a4")
