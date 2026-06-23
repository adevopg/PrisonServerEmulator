# Surgical client patch: stop the post-server-select null-deref crash.
# At VA 0x590e0e (reached only when the menu widget-tree head [0x5eda68] is null /
# selected-server widget not found) change `xor eax,eax` (33 c0, redundant: eax already 0)
# -> `jmp 0x590e48` (eb 38) = the function's clean epilogue.  Stack-safe.
import pefile, shutil, sys, struct
EXE=r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
VA=0x590e0e
OLD=bytes([0x33,0xc0])      # xor eax,eax
NEW=bytes([0xeb,0x38])      # jmp short +0x38 -> 0x590e48
pe=pefile.PE(EXE); ib=pe.OPTIONAL_HEADER.ImageBase
rva=VA-ib
foff=pe.get_offset_from_rva(rva)
pe.close()
with open(EXE,'rb') as f: data=bytearray(f.read())
cur=bytes(data[foff:foff+2])
print("VA %x -> file offset %x ; current bytes = %s"%(VA,foff,cur.hex()))
if cur==NEW:
    print("ALREADY PATCHED."); sys.exit(0)
if cur!=OLD:
    print("UNEXPECTED bytes (expected %s). Aborting."%OLD.hex()); sys.exit(1)
# verify the jump target 0x590e48 epilogue bytes (5f 8b e5 5d c3 = pop edi;mov esp,ebp;pop ebp;ret)
tgt_foff=pe.get_offset_from_rva(0x590e48-ib) if False else foff+ (0x590e48-VA)
epi=bytes(data[tgt_foff:tgt_foff+5])
print("target 0x590e48 bytes = %s (expect 5f8be55dc3)"%epi.hex())
shutil.copyfile(EXE, EXE+".crashpatch.orig")
print("backup -> Carcelclient.exe.crashpatch.orig")
data[foff:foff+2]=NEW
with open(EXE,'wb') as f: f.write(data)
print("PATCHED: %x = %s (jmp 0x590e48)"%(VA,NEW.hex()))
