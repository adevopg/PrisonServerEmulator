import pefile, capstone, struct
PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH); ib = pe.OPTIONAL_HEADER.ImageBase
text=[s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text'][0]
tva=ib+text.VirtualAddress; td=text.get_data()
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
# jumptable at 0x411334 indexed by byte[0x41138c + idx], idx = event-0x43c, range 0..0x28
idxtab=pe.get_data(0x41138c-ib, 0x29)
maxi=max(idxtab)
addrtab=pe.get_data(0x411334-ib,(maxi+1)*4)
ptrs=[struct.unpack('<I',addrtab[i*4:i*4+4])[0] for i in range(maxi+1)]
for e in range(0x29):
    h=ptrs[idxtab[e]]
    if h==0x41045d: print("ping-timer-register EVENT = 0x%x"%(0x43c+e))
# find who fires it: search push of that event then call 0x40ec40
for e in range(0x29):
    if ptrs[idxtab[e]]==0x41045d:
        ev=0x43c+e
        needle=b'\x68'+ev.to_bytes(4,'little')
        i=0
        while True:
            i=td.find(needle,i)
            if i<0: break
            va=tva+i
            off=i-40
            print("\n--- push 0x%x @ %08x ---"%(ev,va))
            for ins in md.disasm(td[off:off+46],tva+off):
                if ins.address<=va+5: print("  %08x: %-8s %s"%(ins.address,ins.mnemonic,ins.op_str))
            i+=1
