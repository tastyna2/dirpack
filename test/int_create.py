import os
import lief

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

def modify_pe(src, dst, packer):
    src_list = os.listdir(os.path.join(src, packer))
    src_list.sort()
    for name in src_list:
        #if name != 'DTCPing.exe':
        #    continue
        nonpack_path = os.path.join(src, 'Notpacked', name)
        nonpacked = lief.PE.parse(nonpack_path)
        knlist = []
        for dll in nonpacked.imports:
            if dll.name.lower() == 'kernel32.dll':
                for api in dll.entries:
                    knlist.append(api.name)

        count_kernel = len(knlist)

        with open(os.path.join(src, packer, name), mode='rb') as f, open(os.path.join(dst, packer, name), mode='wb') as g:
            data = f.read()
            g.write(data)
            f.seek(lfanew, os.SEEK_SET)
            data = f.read(4)
            pesig = int.from_bytes(data, "little")
            f.seek(pesig + imgbs_addr, os.SEEK_SET)
            data = f.read(4)
            image_base = int.from_bytes(data, "little")
            f.seek(pesig + numsec_addr, os.SEEK_SET)
            data = f.read(2)
            num_of_sec = int.from_bytes(data, "little")
            f.seek(pesig + impdir_addr, os.SEEK_SET)
            data = f.read(4)
            addr = int.from_bytes(data, "little")
            offsec = pesig + sectab
            f.seek(offsec, os.SEEK_SET)
            impra = 0
            sec_info = []
            while num_of_sec > 0:
                data = f.read(40)
                secsz = int.from_bytes(data[8:12], "little")
                secrs = int.from_bytes(data[16:20], "little")
                secva = int.from_bytes(data[12:16], "little")
                secra = int.from_bytes(data[20:24], "little")
                chris = int.from_bytes(data[36:40], "little")
                sec_info.append({'secsz': secsz, 'secva': secva, 'secrs': secrs, 'secra': secra, 'chris': chris})
                if addr >= secva and addr < secva + secsz:
                    impra = addr - secva + secra
                num_of_sec -= 1
            if impra:
                dll_list = []
                last_sec, sec_ofst = last_secinfo(sec_info)
                dll_rawaddr = last_sec['secra'] + last_sec['secrs']
                new_thunkra = dll_rawaddr
                f.seek(impra, os.SEEK_SET)
                g.seek(dll_rawaddr, os.SEEK_SET)
                imp_size = 0
                while True:
                    data = f.read(20)
                    new_thunkra += 20
                    if len(data) < 20:
                        g.write(b'\x00' * 20)
                        break
                    g.write(data)
                    imp_size += 20
                    if data == b'\x00' * 20:
                        break
                    thunkva = int.from_bytes(data[16:], "little")
                    thunkra = calc_rawaddr(thunkva, sec_info, image_base)
                    nameva = int.from_bytes(data[12:16], "little")
                    namera = calc_rawaddr(nameva, sec_info, image_base)
                    dll_list.append({'nameva': nameva, 'namera': namera, 'thunkra': thunkra})
                no_kernel = True
                for dll in dll_list:
                    f.seek(dll['namera'], os.SEEK_SET)
                    countch = 0
                    while f.read(1) != b'\x00':
                        countch += 1
                    f.seek(-countch-1, os.SEEK_CUR)
                    dll['name'] = f.read(countch).decode()
                    if dll['name'].lower() == 'kernel32.dll':
                        no_kernel = False
                if no_kernel:
                    g.write(b'\x00' * 20)
                    imp_size += 20
                    new_thunkra += 20
                #g.seek(pesig + impdir_addr, os.SEEK_SET)
                #g.write(calc_vaddr(dll_rawaddr, last_sec).to_bytes(4, byteorder="little"))
                #g.write(imp_size.to_bytes(4, byteorder="little"))
                iat_size = 0
                iat_raddr = new_thunkra
                fva = first_secva(sec_info)
                for dll in dll_list:
                    g.seek(impra, os.SEEK_SET)
                    g.write(calc_vaddr(new_thunkra, last_sec).to_bytes(4, byteorder="little"))
                    #g.seek(dll_rawaddr + 16, os.SEEK_SET)
                    #g.write(calc_vaddr(new_thunkra, last_sec).to_bytes(4, byteorder="little"))
                    dll['new_thunkra'] = new_thunkra
                    f.seek(dll['thunkra'], os.SEEK_SET)
                    g.seek(new_thunkra, os.SEEK_SET)
                    api_vaddr_list = []
                    in_sec = True
                    while True:
                        data = f.read(4)
                        api_vaddr = int.from_bytes(data, "little")
                        if api_vaddr < fva:
                            in_sec = False
                        g.write(data)
                        new_thunkra += 4
                        iat_size += 4
                        if data == b'\x00' * 4:
                            break
                        api_vaddr_list.append(api_vaddr)
                    dll['in_sec'] = in_sec
                    if dll['name'].lower() == 'kernel32.dll' and count_kernel > len(api_vaddr_list):
                        if in_sec:
                            dll['new_thunkra'] = new_thunkra - 4
                        new_thunkra += 4 * (count_kernel - len(api_vaddr_list))
                        iat_size += 4 * (count_kernel - len(api_vaddr_list))
                        g.write(b'\x00' * 4 * (count_kernel - len(api_vaddr_list)))
                    impra += 20
                    dll_rawaddr += 20
                    api_name = []
                    for api in api_vaddr_list:
                        apira = calc_rawaddr(api, sec_info, image_base)
                        if apira is None:
                            api_name.append(api)
                        else:
                            f.seek(apira, os.SEEK_SET)
                            while f.read(1) == b'\x00':
                                continue
                            countch = 1
                            while f.read(1) != b'\x00':
                                countch += 1
                            f.seek(-countch-1, os.SEEK_CUR)
                            api_name.append(f.read(countch).decode())
                    dll['api_name'] = api_name
                if no_kernel:
                    dll_list.append({'nameva': 0, 'name': 'KERNEL32.DLL', 'new_thunkra': new_thunkra, 'api_name': [], 'in_sec': True})
                    g.seek(impra, os.SEEK_SET)
                    g.write(calc_vaddr(new_thunkra, last_sec).to_bytes(4, byteorder="little"))
                    #g.seek(dll_rawaddr + 16, os.SEEK_SET)
                    #g.write(calc_vaddr(new_thunkra, last_sec).to_bytes(4, byteorder="little"))
                    g.seek(new_thunkra, os.SEEK_SET)
                    g.write(b'\x00' * 4 * (count_kernel + 1))
                    new_thunkra += 4 * (count_kernel + 1)
                    iat_size += 4 * (count_kernel + 1)
                dll_rawaddr = last_sec['secra'] + last_sec['secrs']
                impra = calc_rawaddr(addr, sec_info, image_base)
                for dll in dll_list:
                    if dll['nameva'] < fva:
                        g.seek(impra + 12, os.SEEK_SET)
                        g.write(calc_vaddr(new_thunkra, last_sec).to_bytes(4, byteorder="little"))
                    g.seek(dll_rawaddr + 12, os.SEEK_SET)
                    g.write(calc_vaddr(new_thunkra, last_sec).to_bytes(4, byteorder="little"))
                    g.seek(new_thunkra, os.SEEK_SET)
                    dll_name = dll['name'].encode() + b'\x00'
                    g.write(dll_name)
                    new_thunkra += len(dll_name)
                    dll_rawaddr += 20
                    impra += 20
                g.seek(pesig + iatdir_addr, os.SEEK_SET)
                g.write(calc_vaddr(iat_raddr, last_sec).to_bytes(4, byteorder="little"))
                g.write(iat_size.to_bytes(4, byteorder="little"))
                last_addr = fill_kernel(g, count_kernel, dll_list, new_thunkra, last_sec, knlist)
                f.seek(pesig + pos_align, os.SEEK_SET)
                data = f.read(4)
                sec_align = int.from_bytes(data, "little")
                data = f.read(4)
                file_align = int.from_bytes(data, "little")
                file_align = set_falign(g, pesig + pos_align + 4, file_align, sec_info)
                lsec_size = last_addr - last_sec['secra']
                lsec_vsize = - (- lsec_size // sec_align) * sec_align
                lsec_rsize = - (- lsec_size // file_align) * file_align
                g.seek(offsec + 40 * sec_ofst + 8, os.SEEK_SET)
                g.write(lsec_vsize.to_bytes(4, byteorder="little"))
                g.seek(4, os.SEEK_CUR)
                g.write(lsec_rsize.to_bytes(4, byteorder="little"))
                g.seek(last_addr, os.SEEK_SET)
                g.write(b'\x00' * (lsec_rsize - lsec_size))

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

plist = pexist

for p in plist:
    if p != 'RLPack':
        continue
    if not os.path.isdir(os.path.join(dst, p)):
        os.mkdir(os.path.join(dst, p))
    if p != "WinUpack":
        modify_pe(src, dst, p)
