import pefile, capstone

PATH = r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer\Carcelclient.exe"
pe = pefile.PE(PATH)
ib = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b'\x00')==b'.text')
text_va = ib + text.VirtualAddress
data = text.get_data()

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

def dump(va_start, va_end, label=""):
    print(f"\n===== {va_start:08x}..{va_end:08x} {label} =====")
    off = va_start - text_va
    n = va_end - va_start
    for ins in md.disasm(data[off:off+n], va_start):
        # annotate references to the reclusos globals
        ann = ""
        for g,nm in [(0x5eda78,"recluCounter"),(0x5eda70,"srvDataArr"),(0x5eda6c,"srvCount"),
                     (0x5eda68,"prisonTree"),(0x5eda74,"selIdx"),(0x5eda48,"menuBase")]:
            if f"0x{g:x}" in ins.op_str: ann += f"  ; {nm}"
        print(f"  {ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}{ann}")

# region around 0x48b33b: sets [0x5eda78] = 0x4b0950(server_array[idx].field+4 -1, 0)
dump(0x48b2e0, 0x48b3b0, "set recluCounter @48b33b")
# the counter init/anim function
dump(0x4b0950, 0x4b0a10, "counter fn 0x4b0950")
# render reads [0x5eda78] + itoa (reclusos text). search a window
dump(0x590dd0, 0x590f00, "render 0x590dd0 (reads recluCounter+itoa)")
# AVAILABLESERVERS parser 0x4a1f30 (builds data array 0x10/entry)
dump(0x4a1f30, 0x4a2050, "AVAILABLESERVERS parser 0x4a1f30")
