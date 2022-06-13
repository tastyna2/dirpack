import os
import lief

path = '/home/cuckoo/advpacker/RLPack/7z.exe'
data = lief.PE.parse(path)

names = []

for dll in data.imports:
    if dll.name.lower() == 'kernel32.dll':
        for api in dll.entries:
            names.append(api.name)

#print(names)

with open(path, mode="r+b") as f:
    wb = b'\x50\x31\xc0\xa3\x96\x22\x42\x00\x58'
    rl = 0x21d62 - 0x22b00 - 5 - len(wb)
    f.seek(0x9d00)
    f.write(wb)
    f.write(b'\xe9')
    f.write(rl.to_bytes(4, byteorder="little", signed=True))
    f.write(b'\x90')
    f.seek(0xd8)
    f.write(b'\x00\x2b\x02\x00')
