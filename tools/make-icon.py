"""Render the original Firaw radar/network mark as multi-size Windows icons."""
from pathlib import Path
from PIL import Image, ImageDraw
root = Path(__file__).resolve().parents[1]
s = 4
im = Image.new('RGBA', (256*s, 256*s))
d = ImageDraw.Draw(im)
def box(coords): return tuple(v*s for v in coords)
def line(coords, fill, width): d.line([(x*s,y*s) for x,y in coords],fill=fill,width=width*s,joint='curve')
d.rounded_rectangle(box((8,8,248,248)), radius=54*s, fill='#102633', outline='#285061', width=4*s)
d.ellipse(box((50,47,206,203)), outline='#1d6576', width=5*s)
d.ellipse(box((78,75,178,175)), outline='#245264', width=3*s)
line([(128,125),(183,70)],'#39d8f0',9)
line([(80,169),(128,125),(181,169)],'#39d8f0',9)
d.arc(box((50,47,206,203)),270,360,fill='#73efff',width=9*s)
d.ellipse(box((114,111,142,139)),fill='#d6fbff')
for x in [63,166]: d.rounded_rectangle(box((x,154,x+31,185)),radius=8*s,fill='#0b2330',outline='#39d8f0',width=6*s)
d.ellipse(box((173,60,193,80)),fill='#73efff')
im = im.resize((256,256),Image.Resampling.LANCZOS)
icons = root/'src-tauri/icons'
icons.mkdir(exist_ok=True)
im.save(icons/'icon.ico',sizes=[(16,16),(24,24),(32,32),(48,48),(64,64),(128,128),(256,256)])
for size in [32,128,256]: im.resize((size,size),Image.Resampling.LANCZOS).save(icons/f'{size}x{size}.png')
assets = root/'site/public/assets'
assets.mkdir(parents=True,exist_ok=True)
im.save(assets/'icon.png')
(assets/'icon.ico').write_bytes((icons/'icon.ico').read_bytes())
(assets/'logo.svg').write_bytes((root/'assets/logo.svg').read_bytes())
