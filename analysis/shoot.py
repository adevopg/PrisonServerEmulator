import ctypes as C, time, sys, subprocess
from ctypes import wintypes as W
u32=C.windll.user32; gdi=C.windll.gdi32
u32.SetProcessDPIAware()
def find_win():
    res=[]
    @C.WINFUNCTYPE(C.c_bool, W.HWND, W.LPARAM)
    def cb(h,l):
        if u32.IsWindowVisible(h):
            n=u32.GetWindowTextLengthW(h)
            if n:
                b=C.create_unicode_buffer(n+1); u32.GetWindowTextW(h,b,n+1)
                t=b.value
                tu=t.upper()
                if "ONLINE" in tu and "NOTEPAD" not in tu and "VISUAL" not in tu and "CODE" not in tu:
                    res.append((h,t))
        return True
    u32.EnumWindows(cb,0)
    return res
out=sys.argv[1] if len(sys.argv)>1 else "now.png"
# wait for the window
win=None
for _ in range(120):
    w=find_win()
    if w: win=w[0]; break
    time.sleep(0.1)
if not win: print("no game window"); sys.exit()
h,title=win
print("window:",title)
u32.ShowWindow(h,9)      # restore
u32.SetForegroundWindow(h)
time.sleep(0.3)
# capture full virtual screen via BitBlt of the window rect
r=W.RECT(); u32.GetWindowRect(h,C.byref(r))
w_,h_=r.right-r.left, r.bottom-r.top
hdc=u32.GetDC(0)
mdc=gdi.CreateCompatibleDC(hdc)
bmp=gdi.CreateCompatibleBitmap(hdc,w_,h_)
gdi.SelectObject(mdc,bmp)
gdi.BitBlt(mdc,0,0,w_,h_,hdc,r.left,r.top,0x00CC0020)
# save via GDI+ ... simpler: use PrintWindow into DIB and write BMP manually
class BITMAPINFOHEADER(C.Structure):
    _fields_=[("biSize",W.DWORD),("biWidth",W.LONG),("biHeight",W.LONG),("biPlanes",W.WORD),
              ("biBitCount",W.WORD),("biCompression",W.DWORD),("biSizeImage",W.DWORD),
              ("biXPelsPerMeter",W.LONG),("biYPelsPerMeter",W.LONG),("biClrUsed",W.DWORD),("biClrImportant",W.DWORD)]
bi=BITMAPINFOHEADER(); bi.biSize=40; bi.biWidth=w_; bi.biHeight=-h_; bi.biPlanes=1; bi.biBitCount=24; bi.biCompression=0
stride=((w_*3+3)//4)*4
buf=(C.c_char*(stride*h_))()
gdi.GetDIBits(mdc,bmp,0,h_,buf,C.byref(bi),0)
# write BMP
import struct
fsize=54+stride*h_
with open(out,"wb") as f:
    f.write(b'BM'+struct.pack('<IHHI',fsize,0,0,54))
    f.write(struct.pack('<IiiHHIIiiII',40,w_,-h_,1,24,0,stride*h_,2835,2835,0,0))
    f.write(buf.raw)
print("saved",out,w_,"x",h_)
