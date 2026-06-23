# Third client patch: suppress the "OffenceList is empty after LeechClassInfoPacket()"
# error dialog. At 0x4a4a7a the CLASSINFO handler does `test ebx,ebx (classArr); jne 0x4a4a90`
# -> if classArr is null it shows the error (call 0x50a440) and aborts the char-create/
# prison-list load. Change `jne` (75 14) to `jmp` (eb 14) so it ALWAYS takes the OK path.
# (The preview render is already guarded against null classArr by crashpatch2.)
import pefile, shutil, sys
EXE=r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
VA=0x4a4a7a
OLD=bytes([0x75,0x14])   # jne 0x4a4a90
NEW=bytes([0xeb,0x14])   # jmp 0x4a4a90
pe=pefile.PE(EXE); ib=pe.OPTIONAL_HEADER.ImageBase
foff=pe.get_offset_from_rva(VA-ib); pe.close()
data=bytearray(open(EXE,'rb').read())
cur=bytes(data[foff:foff+2])
print("VA %x foff %x current=%s"%(VA,foff,cur.hex()))
if cur==NEW: print("ALREADY PATCHED."); sys.exit(0)
if cur!=OLD: print("UNEXPECTED (expected %s) - dumping 0x4a4a70..0x4a4a90:"%OLD.hex(), bytes(data[foff-10:foff+22]).hex()); sys.exit(1)
shutil.copyfile(EXE, EXE+".crashpatch3.orig")
data[foff:foff+2]=NEW
open(EXE,'wb').write(data)
print("PATCHED 0x4a4a7a jne->jmp (suppress OffenceList-empty error). backup: .crashpatch3.orig")
