import pefile, capstone, struct
PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH); ib = pe.OPTIONAL_HEADER.ImageBase
tab=pe.get_data(0x40ff88-ib, 11*4)
ptrs=[struct.unpack('<I',tab[i*4:i*4+4])[0] for i in range(11)]
names={0x40fef5:'PING-ECHO(0x423 PONG)'}
for i,p in enumerate(ptrs):
    tag=''
    if p==0x40fef5: tag=' <== PING/PONG'
    print("  small-op %d (0x%x): 0x%08x%s"%(i,i,p,tag))
