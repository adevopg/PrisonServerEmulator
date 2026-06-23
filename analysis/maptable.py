import pefile
PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH); ib = pe.OPTIONAL_HEADER.ImageBase
def rd(va,n): return pe.get_data(va-ib, n)
BYTE_TBL=0x40c748   # byte index table, indexed by (rebased_opcode - 1)
DWORD_TBL=0x40c6e8  # dword handler table, indexed by byteTable value
# dispatcher: eax=rebased opcode; dec; cmp 0x7c (ja default); idx=byte[eax+BYTE_TBL]; jmp [idx*4+DWORD_TBL]
# so for rebased r in 1..0x7d: idx=byte[BYTE_TBL + (r-1)]; handler=dword[DWORD_TBL + idx*4]
btbl = rd(BYTE_TBL, 0x7d)
# dword table size unknown; read enough (max idx*4)
maxidx = max(btbl)
dtbl = rd(DWORD_TBL, (maxidx+1)*4)
def handler(r):
    idx = btbl[r-1]
    return int.from_bytes(dtbl[idx*4:idx*4+4],'little')
named = {0x40a59e:"ACCOUNT", 0x40aa56:"AVAILABLESERVERS", 0x40b7bb:"AVAIL/zlib(0x13d4)",
         0x40a4ae:"KICKED", 0x40aaa4:"SERVERADDED?", 0x40abd7:"CLASSINFO?", 0x40a4ae:"KICKED"}
print("rebased  wire    handler     name")
seen={}
for r in range(1,0x7e):
    h=handler(r)
    wire = r + 0x1388
    tag = named.get(h,"")
    seen.setdefault(h,[]).append(wire)
    if tag or h in named:
        print(f"  0x{r:02x}    0x{wire:04x}  0x{h:08x}  {tag}")
print("\n--- which wire opcode hits each handler of interest ---")
for h,nm in [(0x40a59e,"ACCOUNT"),(0x40aa56,"AVAILABLESERVERS"),(0x40b7bb,"zlib-list 0x40b7bb"),
             (0x40aaa4,"SERVERADDED 0x40aaa4"),(0x40abd7,"CLASSINFO 0x40abd7"),(0x40a4ae,"KICKED")]:
    ws=seen.get(h)
    print(f"  {nm:24s} handler 0x{h:08x} <- wire {[hex(w) for w in ws] if ws else 'NONE'}")
