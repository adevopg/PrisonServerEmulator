import re, glob, os
os.chdir(r"c:\Users\Administrator\Desktop\PrisonServer\PrisonServer\PrisonServer")
BS=chr(92)  # backslash
nge=BS+"nge"+BS
alln=set()
for p in glob.glob('*.pak'):
    try: d=open(p,'rb').read()
    except: continue
    for m in re.finditer(rb'[ -~]{5,}\.R3D', d, re.IGNORECASE):
        s=m.group().decode('latin1'); low=s.lower()
        if nge in low and 'puerta' not in low and 'plantilla' not in low:
            alln.add(s)
for n in sorted(alln): print(n)
print('TOTAL', len(alln))
