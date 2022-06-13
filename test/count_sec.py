import os
import lief
from collections import defaultdict

lfanew = 0x3c
numsec_addr = 0x06
imgbs_addr = 0x34
pos_align = 0x38
impdir_addr = 0x80
impdir_size = 0x84
iatdir_addr = 0xd8
iatdir_size = 0xdc
sectab = 0xf8

impdir = {'hint': 0, 'time': 4, 'chain': 8, 'name': 12, 'thunk': 16}

def set_falign(fo, ofst, falign, sec_list):
    min_align = falign
    invalid_align = False
    for si in sec_list:
        if si['secra'] % min_align != 0 and min_align > si['secra']:
            min_align = si['secra']
            invalid_align = True
    if invalid_align:
        fo.seek(ofst, os.SEEK_SET)
        fo.write(min_align.to_bytes(4, byteorder="little"))
    return min_align

def first_secva(sec_list):
    fva = sec_list[0]['secva']
    for si in sec_list:
        if fva > si['secva']:
            fva = si['secva']
    return fva

def calc_rawaddr(vaddr, sec_list, imgbs):
    is_fileoffset = True
    for si in sec_list:
        if vaddr >= si['secva'] and vaddr < si['secva'] + si['secsz']:
            return vaddr - si['secva'] + si['secra']
        if vaddr >= si['secva']:
            is_fileoffset = False
    if is_fileoffset:
        return vaddr

def last_secinfo(sec_list):
    tmp = 0
    idx = 0
    pos = 0
    for si in sec_list:
        if tmp < si['secra'] + si['secrs']:
            tmp = si['secra'] + si['secrs']
            info = si
            pos = idx
        idx += 1
    return info, pos

def calc_vaddr(raddr, section):
    return section['secva'] + raddr - section['secra']

def fill_kernel(fo, count_kernel, dlls, position, section, knlist):
    pos = position
    for dll in dlls:
        offset = dll['new_thunkra']
        for api in dll['api_name']:
            if dll['in_sec']:
                break
            fo.seek(offset, os.SEEK_SET)
            if isinstance(api, int):
                fo.write(api.to_bytes(4, byteorder="little"))
                offset += 4
            else:
                fo.write(calc_vaddr(pos, section).to_bytes(4, byteorder="little"))
                offset += 4
                blank = b'\x00\x00'
                input_byte = blank + api.encode()
                fo.seek(pos, os.SEEK_SET)
                fo.write(input_byte)
                pos += len(input_byte)
        if dll['name'].lower() == 'kernel32.dll':
            rem = count_kernel - len(dll['api_name'])
            for api in knlist:
                if rem < 1:
                    break
                if not api in dll['api_name']:
                    fo.seek(offset, os.SEEK_SET)
                    fo.write(calc_vaddr(pos, section).to_bytes(4, byteorder="little"))
                    offset += 4
                    blank = b'\x00\x00'
                    input_byte = blank + api.encode()
                    fo.seek(pos, os.SEEK_SET)
                    fo.write(input_byte)
                    pos += len(input_byte)
                    rem -= 1
    return pos

def count_sec(dir, sec_name):
    src_list = os.listdir(dir)
    src_list.sort()
    for name in src_list:
        with open(os.path.join(dir, name), mode='rb') as f:
            f.seek(lfanew, os.SEEK_SET)
            data = f.read(4)
            pesig = int.from_bytes(data, "little")
            f.seek(pesig + imgbs_addr, os.SEEK_SET)
            data = f.read(4)
            image_base = int.from_bytes(data, "little")
            f.seek(pesig + numsec_addr, os.SEEK_SET)
            data = f.read(2)
            num_of_sec = int.from_bytes(data, "little")
            offsec = pesig + sectab
            f.seek(offsec, os.SEEK_SET)
            while num_of_sec > 0:
                data = f.read(40)
                sec_name[data[:8].split(b'\x00')[0]] += 1
                num_of_sec -= 1

plist = ["ASPack", "BeRoEXEPacker", "FSG", "JDPack", "MEW", "MPRESS", "Molebox",
    "NSPack", "Neolite", "PECompact", "PEtite", "Packman", "RLPack", "UPX", "WinUpack",
    "Yoda's Protector", "Yoda's Crypter", "eXpressor", "exe32pack"]

pexist = []

homedir = '/home/cuckoo'
src_dir = 'PackDataset'
src = os.path.join(homedir, src_dir)
notpackdir = os.path.join(homedir, src_dir, 'Notpacked')

for p in plist:
    if os.path.isdir(os.path.join(src, p)):
        pexist.append(p)

plist = pexist

sec_name = defaultdict(int)

count_sec(notpackdir, sec_name)
for p in plist:
    if p == "WinUpack":
        continue
    path = os.path.join(src, p)
    count_sec(path, sec_name)

print(sec_name)
sec_name = [i[0] for i in sorted(sec_name.items(), key=lambda x: x[1], reverse=True)]
print(sec_name)
print(len(sec_name))
data = lief.PE.parse(os.path.join(src, 'MEW', '7z.exe'))
for s in data.sections:
    print(s.name)
    if s.name == '\x02\\xd2u\\xdb\\x8a\x16\\xeb\\xd4':
        print(True)
    else:
        print(False)

print(b'\x30\xdb\xea\x5c')
