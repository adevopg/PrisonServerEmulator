# Second surgical client patch: guard the prison-select PREVIEW render against a
# null class array [0x5ec5d0] (CLASSINFO not processed in time) -> crash @0x561f75.
# Region 0x561f64..0x561f77 (20 bytes) is rewritten to test classArr(ecx); if null,
# edx=0 (the strlen/dup helper 0x41c0b2 handles null safely); else load the name.
import pefile, shutil, sys
EXE=r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
VA=0x561f64
OLD=bytes([0x8d,0x04,0x80, 0x38,0x1d,0x1a,0x1f,0x5c,0x00, 0x74,0x06, 0x8b,0x54,0x81,0x04, 0xeb,0x03, 0x8b,0x14,0x81])
#            lea eax,[eax+eax*4] | cmp byte[0x5c1f1a],bl     | je +6  | mov edx,[ecx+eax*4+4] | jmp +3 | mov edx,[ecx+eax*4]
NEW=bytes([0x8d,0x04,0x80,       # lea eax,[eax+eax*4]
           0x85,0xc9,            # test ecx,ecx           (classArr null?)
           0x75,0x04,            # jne +4 -> 0x561f6f      (non-null: load name)
           0x33,0xd2,            # xor edx,edx             (null: edx=0, safe)
           0xeb,0x09,            # jmp +9 -> 0x561f78      (skip to push edx)
           0x8b,0x14,0x81,       # mov edx,[ecx+eax*4]     (entry+0 = class name)
           0x90,0x90,0x90,0x90,0x90,0x90])  # nop padding to 0x561f78
assert len(OLD)==20 and len(NEW)==20, (len(OLD),len(NEW))
pe=pefile.PE(EXE); ib=pe.OPTIONAL_HEADER.ImageBase
foff=pe.get_offset_from_rva(VA-ib); pe.close()
data=bytearray(open(EXE,'rb').read())
cur=bytes(data[foff:foff+20])
print("VA %x foff %x"%(VA,foff))
print("current:", cur.hex())
if cur==NEW: print("ALREADY PATCHED."); sys.exit(0)
if cur!=OLD: print("UNEXPECTED bytes; expected", OLD.hex(), "- ABORT."); sys.exit(1)
shutil.copyfile(EXE, EXE+".crashpatch2.orig")
data[foff:foff+20]=NEW
open(EXE,'wb').write(data)
print("PATCHED 0x561f64 -> classArr-null guard. backup: Carcelclient.exe.crashpatch2.orig")
print("new:", NEW.hex())
