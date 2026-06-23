# inject_name.py - make the prison list show the REAL prison name from MySQL.
#
# AVAILABLESERVERS parser @0x4a1f30 sets entry+0xc (display name) from the prison
# widget tree (head @0x5eda68); our flow never builds that tree -> not-found ->
# copies literal "(null)". We redirect the not-found branch (0x4a2062) to a code
# cave that allocates a buffer with the CLIENT's allocator (0x41bed5, so it stays
# freeable) and copies our DB name into it. (Pointing entry+0xc at non-heap memory
# crashed the client when it later free()s that field.)
import ctypes as C, ctypes.wintypes as W, subprocess, struct, time, os
k32=C.windll.kernel32
PROCESS_ALL = 0x000F0000|0x00100000|0xFFFF
MALLOC=0x41bed5      # client allocator (callee-cleans arg); entry+0xc is freed with its match

def pid_of(name):
    out=subprocess.check_output(['tasklist','/fi','imagename eq %s'%name,'/fo','csv','/nh'],text=True)
    for line in out.splitlines():
        if name.lower() in line.lower():
            try: return int(line.split(',')[1].strip('"'))
            except: pass
    return None

def get_prison_from_db():
    name="La Prision"; reclusos=0
    mysql=r"C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe"
    try:
        out=subprocess.check_output([mysql,"-u","Inna","-pLadyamy89","prison","-N","-B","-e",
            "SELECT name, population FROM game_servers ORDER BY sort_order LIMIT 1;"],
            text=True, stderr=subprocess.DEVNULL)
        row=out.strip().split('\n')[0].split('\t')
        if len(row)>=2: name=row[0]; reclusos=int(row[1])
    except Exception as e:
        print("[!] MySQL query failed (%s); using env/defaults"%e)
    return os.environ.get("PRISON_NAME", name), int(os.environ.get("RECLUSOS", reclusos))

def main():
    name, reclusos = get_prison_from_db()
    print("[*] prison name='%s'  reclusos=%d"%(name, reclusos))
    nb = name.encode('latin1','replace')[:120]+b'\x00'
    namelen1 = len(nb)   # includes the null

    pid=None
    for _ in range(80):
        pid=pid_of("Carcelclient.exe")
        if pid: break
        time.sleep(0.2)
    if not pid: print("[!] client not found"); return
    h=k32.OpenProcess(PROCESS_ALL, False, pid)
    if not h: print("[!] OpenProcess failed", k32.GetLastError()); return
    print("[*] attached pid", pid)
    def wr(addr,data):
        n=C.c_size_t()
        if not k32.WriteProcessMemory(h,C.c_void_p(addr),data,len(data),C.byref(n)):
            print("[!] write %x failed %d"%(addr,k32.GetLastError())); return False
        return True
    def protect(addr,size):
        old=W.DWORD(); k32.VirtualProtectEx(h,C.c_void_p(addr),size,0x40,C.byref(old))

    k32.VirtualAllocEx.restype=C.c_void_p
    cave=int(k32.VirtualAllocEx(h,None,0x200,0x3000,0x40))
    if not cave: print("[!] alloc failed",k32.GetLastError()); return
    print("[*] cave @ %08x"%cave)

    NAME_OFF=0x100
    name_addr=cave+NAME_OFF
    wr(name_addr, nb)

    # cave stub @ cave+0:
    #   push namelen1 ; call MALLOC ; mov ebx,[0x5eda70] ; mov [edi+ebx+0xc],eax
    #   push esi/edi/ecx ; mov esi,name ; mov edi,eax ; mov ecx,namelen1 ; rep movsb
    #   pop ecx/edi/esi ; jmp 0x4a2092
    stub=b''
    if namelen1<128: stub+=b'\x6a'+bytes([namelen1])         # push imm8
    else: stub+=b'\x68'+struct.pack('<I',namelen1)           # push imm32
    call_off=len(stub)
    stub+=b'\xe8'+struct.pack('<I',(MALLOC-(cave+call_off+5))&0xffffffff)  # call MALLOC
    stub+=b'\x8b\x1d'+struct.pack('<I',0x5eda70)             # mov ebx,[0x5eda70]
    stub+=b'\x89\x44\x1f\x0c'                                 # mov [edi+ebx+0xc],eax
    stub+=b'\x56\x57\x51'                                     # push esi; push edi; push ecx
    stub+=b'\xbe'+struct.pack('<I',name_addr)                # mov esi, name_addr
    stub+=b'\x8b\xf8'                                         # mov edi, eax
    stub+=b'\xb9'+struct.pack('<I',namelen1)                 # mov ecx, namelen1
    stub+=b'\xfc'                                             # cld (clear DF -> copy forward)
    stub+=b'\xf3\xa4'                                         # rep movsb
    stub+=b'\x59\x5f\x5e'                                     # pop ecx; pop edi; pop esi
    jmp_off=len(stub)
    stub+=b'\xe9'+struct.pack('<I',(0x4a2092-(cave+jmp_off+5))&0xffffffff) # jmp 0x4a2092
    wr(cave, stub)

    # patch 0x4a2062 -> jmp cave
    site=0x4a2062
    protect(site,8)
    wr(site, b'\xe9'+struct.pack('<I',(cave-(site+5))&0xffffffff))
    k32.FlushInstructionCache(h,C.c_void_p(site),8)
    print("[+] patched parser 0x4a2062 -> malloc+copy DB name ('%s')"%name)

main()
