import os
import lief
import shutil
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

CNT_CODE = 0x00000020
CNT_INITIALIZED_DATA = 0x00000040
CNT_UNINITIALIZED_DATA = 0x00000080
MEM_EXECUTE = 0x20000000
MEM_READ = 0x40000000
MEM_WRITE = 0x80000000

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

def count_sec(dir, packer, name):
    with open(os.path.join(dir, packer, name), mode='rb') as f:
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
        sec_chr = {'code': 0, 'ini': 0, 'unini': 0, 'mexe': 0, 'mread': 0, 'mwrite': 0}
        sec_chr['num_sec'] = num_of_sec
        sec_chr['offsec'] = offsec
        while num_of_sec > 0:
            data = int.from_bytes(f.read(40)[36:], "little")
            if data & CNT_CODE == CNT_CODE:
                sec_chr['code'] += 1
            if data & CNT_INITIALIZED_DATA == CNT_INITIALIZED_DATA:
                sec_chr['ini'] += 1
            if data & CNT_UNINITIALIZED_DATA == CNT_UNINITIALIZED_DATA:
                sec_chr['unini'] += 1
            if data & MEM_EXECUTE == MEM_EXECUTE:
                sec_chr['mexe'] += 1
            if data & MEM_READ == MEM_READ:
                sec_chr['mread'] += 1
            if data & MEM_WRITE == MEM_WRITE:
                sec_chr['mwrite'] += 1
            num_of_sec -= 1
        return sec_chr

def modify_pe(src, dst, name, packer):
    modi_chr = {'mexe': 0, 'mread': 0, 'mwrite': 0}
    chr_dict = dict()
    for p in packer:
        if not os.path.isfile(os.path.join(src, p, name)) or p == "WinUpack":
            continue
        chr_dict[p] = count_sec(src, p, name)
        for k in modi_chr:
            if modi_chr[k] < chr_dict[p][k]:
                modi_chr[k] = chr_dict[p][k]
    np_chr = count_sec(src, 'Notpacked', name)
    for p in packer:
        if not os.path.isdir(os.path.join(dst, p)):
            os.mkdir(os.path.join(dst, p))
        if not os.path.isfile(os.path.join(src, p, name)) or p == "WinUpack":
            continue
        sec_chr = chr_dict[p]
        num_of_sec = sec_chr['num_sec']
        with open(os.path.join(src, p, name), mode='rb') as f, open(os.path.join(dst, p, name), mode='wb') as g:
            data = f.read()
            g.write(data)
            f.seek(sec_chr['offsec'] + 36, os.SEEK_SET)
            g.seek(sec_chr['offsec'] + 36, os.SEEK_SET)
            while num_of_sec > 0:
                data = int.from_bytes(f.read(4), "little")
                if data & CNT_CODE != CNT_CODE and sec_chr['code'] < np_chr['code']:
                    data |= CNT_CODE
                    sec_chr['code'] += 1
                elif data & CNT_CODE == CNT_CODE and sec_chr['code'] > np_chr['code']:
                    data &= ~CNT_CODE
                    sec_chr['code'] -= 1
                if data & CNT_INITIALIZED_DATA != CNT_INITIALIZED_DATA and sec_chr['ini'] < np_chr['ini']:
                    data |= CNT_INITIALIZED_DATA
                    sec_chr['ini'] += 1
                elif data & CNT_INITIALIZED_DATA == CNT_INITIALIZED_DATA and sec_chr['ini'] > np_chr['ini']:
                    data &= ~CNT_INITIALIZED_DATA
                    sec_chr['ini'] -= 1
                if data & CNT_UNINITIALIZED_DATA != CNT_UNINITIALIZED_DATA and sec_chr['unini'] < np_chr['unini']:
                    data |= CNT_UNINITIALIZED_DATA
                    sec_chr['unini'] += 1
                elif data & CNT_UNINITIALIZED_DATA == CNT_UNINITIALIZED_DATA and sec_chr['unini'] > np_chr['unini']:
                    data &= ~CNT_UNINITIALIZED_DATA
                    sec_chr['unini'] -= 1
                if data & MEM_EXECUTE != MEM_EXECUTE and sec_chr['mexe'] < modi_chr['mexe']:
                    data |= MEM_EXECUTE
                    sec_chr['mexe'] += 1
                if data & MEM_READ != MEM_READ and sec_chr['mread'] < modi_chr['mread']:
                    data |= MEM_READ
                    sec_chr['mread'] += 1
                if data & MEM_WRITE != MEM_WRITE and sec_chr['mwrite'] < modi_chr['mwrite']:
                    data |= MEM_WRITE
                    sec_chr['mwrite'] += 1
                g.write(data.to_bytes(4, byteorder="little"))
                f.seek(36, os.SEEK_CUR)
                g.seek(36, os.SEEK_CUR)
                num_of_sec -= 1

plist = ["ASPack", "BeRoEXEPacker", "FSG", "JDPack", "MEW", "MPRESS", "Molebox",
    "NSPack", "Neolite", "PECompact", "PEtite", "Packman", "RLPack", "UPX", "WinUpack",
    "Yoda's Protector", "Yoda's Crypter", "eXpressor", "exe32pack"]

pexist = []

homedir = '/home/cuckoo'
src_dir = 'PackDataset'
dst_dir = 'advpacker'
src = os.path.join(homedir, src_dir)
dst = os.path.join(homedir, dst_dir)

for p in plist:
    if os.path.isdir(os.path.join(src, p)):
        pexist.append(p)
    if os.path.isdir(os.path.join(dst, p)):
        shutil.rmtree(os.path.join(dst, p))

plist = pexist
flist = os.listdir(os.path.join(src, "Notpacked"))
flist.sort()

for name in flist:
    modify_pe(src, dst, name, plist)
