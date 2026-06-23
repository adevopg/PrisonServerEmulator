import pefile, capstone
PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH); ib = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b'\x00')==b'.text')
tva=ib+text.VirtualAddress; tdata=text.get_data()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32); md.detail=True
# find refs to the "CARGANDO ESCENA %s 3D DE LA ZONA" string (VA 0x5a13ba) as push imm
for strva in (0x5a13ba,):
    needle=b'\x68'+strva.to_bytes(4,'little')
    i=0
    while True:
        i=tdata.find(needle,i)
        if i<0: break
        print("push 0x%x ('CARGANDO ESCENA') @ 0x%08x"%(strva, tva+i))
        i+=1
# Also map all world server->client opcodes (full dispatch table) to handlers, print range
btbl=pe.get_data(0x40c748-ib,0x7d); maxidx=max(btbl); dtbl=pe.get_data(0x40c6e8-ib,(maxidx+1)*4)
print("\n=== full opcode->handler table (wire 0x1389..0x1404) ===")
for r in range(1,0x7e):
    idx=btbl[r-1]; h=int.from_bytes(dtbl[idx*4:idx*4+4],'little')
    if h!=0x40c5b1:  # skip default/no-op
        print("  wire 0x%04x -> 0x%08x"%(r+0x1388, h))
