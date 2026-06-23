import pefile, capstone
PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH); ib = pe.OPTIONAL_HEADER.ImageBase
data_all=open(PATH,'rb').read()
text = next(s for s in pe.sections if s.Name.rstrip(b'\x00')==b'.text')
tva=ib+text.VirtualAddress; tdata=text.get_data()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32); md.detail=True

# IAT: gethostbyname / connect / htons / inet_addr / WSAConnect
iat={}
for e in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in e.imports:
        if imp.name: iat[imp.name.decode()]=imp.address
for fn in ['gethostbyname','connect','inet_addr','htons','sendto','recvfrom','socket','WSAStringToAddressA','getaddrinfo']:
    if fn in iat: print("IAT %s = 0x%08x"%(fn, iat[fn]))

# search for port 25001 (0x61a9) as immediate
needle=(25001).to_bytes(2,'little')
print("\n=== '25001' (0x61a9) immediate refs in .text ===")
i=0
while True:
    i=tdata.find(needle,i)
    if i<0: break
    # show as push/mov context
    va=tva+i
    print("  0x%08x"%va)
    i+=1
    if va>tva+text.SizeOfRawData: break

# search strings for prisonserver / world host / .skf
print("\n=== candidate host/ip strings ===")
import re
for pat in [rb'prisonserver[^\x00]*', rb'212\.227[^\x00]*', rb'[a-z0-9.-]+\.com', rb'[a-z0-9_]+\.skf', rb'GameServer[^\x00]*', rb'WorldServer[^\x00]*']:
    for m in re.finditer(pat, data_all, re.I):
        s=m.group(0)
        if 4<len(s)<60:
            # map to VA
            fo=m.start(); va=None
            for sec in pe.sections:
                if sec.PointerToRawData<=fo<sec.PointerToRawData+sec.SizeOfRawData:
                    va=ib+sec.VirtualAddress+(fo-sec.PointerToRawData); break
            print("  0x%s @0x%x: %s"%(format(va,'08x') if va else '????', fo, s[:50]))
