import os
import lief
import shutil

lfanew = 0x3c
numsec_addr = 0x06
offep = 0x28
imgbs_addr = 0x34
pos_align = 0x38
sizimg_addr = 0x50
sizhead_addr = 0x54
impdir_addr = 0x80
impdir_size = 0x84
iatdir_addr = 0xd8
iatdir_size = 0xdc
sectab = 0xf8

impdir = {'hint': 0, 'time': 4, 'chain': 8, 'name': 12, 'thunk': 16}

def calc_rawaddr(vaddr, sec_list):
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
        if tmp <= si['secra'] + si['secrs']:
            tmp = si['secra'] + si['secrs']
            info = si
            pos = idx
        idx += 1
    return info, pos

def calc_vaddr(raddr, section):
    return section['secva'] + raddr - section['secra']

def fill_iat(fo, count_dll, dlls, position, section, api_list):
    pos = position
    for dll in dlls:
        offset = dll['new_thunkra'] + len(dll['api_name']) * 4
        if dll['name'].lower() in api_list:
            rem = count_dll[dll['name'].lower()] - len(dll['api_name'])
            for api in api_list[dll['name'].lower()]:
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
    fo.seek(pos, os.SEEK_SET)
    fo.write(b'\x00\x00')
    pos += 2
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
        count_dll = {'kernel32.dll': 0, 'user32.dll': 0}
        api_list = dict()
        for dll in nonpacked.imports:
            if dll.name.lower() in count_dll:
                knlist = []
                for api in dll.entries:
                    knlist.append(api.name)
                count_dll[dll.name.lower()] = len(knlist)
                api_list[dll.name.lower()] = knlist

        with open(os.path.join(src, packer, name), mode='rb') as f, open(os.path.join(dst, packer, name), mode='wb') as g:
            data = f.read()
            g.write(data)
            f.seek(lfanew, os.SEEK_SET)
            data = f.read(4)
            pesig = int.from_bytes(data, "little")
            f.seek(pesig + offep, os.SEEK_SET)
            data = f.read(4)
            epva = int.from_bytes(data, "little")
            f.seek(pesig + imgbs_addr, os.SEEK_SET)
            data = f.read(4)
            image_base = int.from_bytes(data, "little")
            f.seek(pesig + numsec_addr, os.SEEK_SET)
            data = f.read(2)
            num_of_sec = int.from_bytes(data, "little")
            f.seek(pesig + pos_align, os.SEEK_SET)
            data = f.read(4)
            salign = int.from_bytes(data, byteorder="little")
            data = f.read(4)
            falign = int.from_bytes(data, byteorder="little")
            f.seek(pesig + sizimg_addr, os.SEEK_SET)
            data = f.read(4)
            size_image = int.from_bytes(data, "little")
            f.seek(pesig + sizhead_addr, os.SEEK_SET)
            data = f.read(4)
            size_header = int.from_bytes(data, "little")
            f.seek(pesig + impdir_addr, os.SEEK_SET)
            data = f.read(4)
            addr = int.from_bytes(data, "little")
            data = f.read(4)
            oldimpsiz = int.from_bytes(data, "little")
            offsec = pesig + sectab
            f.seek(offsec, os.SEEK_SET)
            impra = 0

            #record section
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
                print(packer, ':', name)

                #record dll info
                while True:
                    data = f.read(20)
                    g.write(data)
                    new_thunkra += 20
                    imp_size += 20
                    if data == b'\x00' * 20 or not data:
                        break
                    thunkva = int.from_bytes(data[16:], "little")
                    thunkra = calc_rawaddr(thunkva, sec_info)
                    nameva = int.from_bytes(data[12:16], "little")
                    namera = calc_rawaddr(nameva, sec_info)
                    dll_list.append({'namera': namera, 'thunkra': thunkra, 'thunkva': thunkva})
                no_dll = dict() #add
                for k in api_list:
                    no_dll[k] = True

                #record dll name
                for dll in dll_list:
                    f.seek(dll['namera'], os.SEEK_SET)
                    countch = 0
                    while f.read(1) != b'\x00':
                        countch += 1
                    f.seek(-countch-1, os.SEEK_CUR)
                    dll['name'] = f.read(countch).decode()
                    if dll['name'].lower() in no_dll: #add
                        no_dll[dll['name'].lower()] = False
                for k in no_dll: #add
                    if no_dll[k]:
                        g.write(b'\x00' * 20)
                        imp_size += 20
                        new_thunkra += 20
                g.seek(pesig + impdir_addr, os.SEEK_SET)
                g.write(calc_vaddr(dll_rawaddr, last_sec).to_bytes(4, byteorder="little"))
                g.write(imp_size.to_bytes(4, byteorder="little"))
                iat_size = 0
                iat_raddr = new_thunkra
                for dll in dll_list:
                    g.seek(dll_rawaddr, os.SEEK_SET)
                    g.write(calc_vaddr(new_thunkra, last_sec).to_bytes(4, byteorder="little"))
                    g.seek(dll_rawaddr + 16, os.SEEK_SET)
                    g.write(calc_vaddr(new_thunkra, last_sec).to_bytes(4, byteorder="little"))
                    dll['new_thunkra'] = new_thunkra
                    f.seek(dll['thunkra'], os.SEEK_SET)
                    g.seek(new_thunkra, os.SEEK_SET)
                    num_of_api = 0

                    # copy api virtual address in import address table
                    api_vaddr_list = []
                    while True:
                        data = f.read(4)
                        g.write(data)
                        new_thunkra += 4
                        iat_size += 4
                        if data == b'\x00' * 4:
                            break
                        num_of_api += 1
                        api_vaddr = int.from_bytes(data, "little")
                        api_vaddr_list.append(api_vaddr)
                    dll['num_of_api'] = num_of_api

                    #add
                    if dll['name'].lower() in count_dll and count_dll[dll['name'].lower()] > len(api_vaddr_list):
                        new_thunkra += 4 * (count_dll[dll['name'].lower()] - len(api_vaddr_list))
                        iat_size += 4 * (count_dll[dll['name'].lower()] - len(api_vaddr_list))
                        g.write(b'\x00' * 4 * (count_dll[dll['name'].lower()] - len(api_vaddr_list)))
                    dll_rawaddr += 20

                    #record api names
                    api_name = []
                    for api in api_vaddr_list:
                        apira = calc_rawaddr(api, sec_info)
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
                            if api_name[-1] == "VirtualProtect":
                                vpadr = calc_vaddr(dll['new_thunkra'], last_sec) + 4 * (len(api_name) - 1)
                    dll['api_name'] = api_name

                nodll_idx = []
                for k in no_dll:
                    if no_dll[k]:
                        nodll_idx.append(len(dll_list))
                        dll_list.append({'name': k.upper(), 'new_thunkra': new_thunkra, 'api_name': [], 'num_of_api': 0})
                        g.seek(dll_rawaddr, os.SEEK_SET)
                        g.write(calc_vaddr(new_thunkra, last_sec).to_bytes(4, byteorder="little"))
                        g.seek(dll_rawaddr + 16, os.SEEK_SET)
                        g.write(calc_vaddr(new_thunkra, last_sec).to_bytes(4, byteorder="little"))
                        dll_rawaddr += 20
                        g.seek(new_thunkra, os.SEEK_SET)
                        g.write(b'\x00' * 4 * (count_dll[k] + 1))
                        new_thunkra += 4 * (count_dll[k]+1)
                        iat_size += 4 * (count_dll[k]+1)
                dll_rawaddr = last_sec['secra'] + last_sec['secrs']
                for idx in nodll_idx:
                    dll_rawaddr = last_sec['secra'] + last_sec['secrs'] + 20 * idx
                    g.seek(dll_rawaddr + 12, os.SEEK_SET)
                    g.write(calc_vaddr(new_thunkra, last_sec).to_bytes(4, byteorder="little"))
                    g.seek(new_thunkra, os.SEEK_SET)
                    dll_name = dll_list[idx]['name'].encode() + b'\x00'
                    g.write(dll_name)
                    new_thunkra += len(dll_name)
                if not packer == "PEtite":
                    g.seek(pesig + iatdir_addr, os.SEEK_SET)
                    g.write(calc_vaddr(iat_raddr, last_sec).to_bytes(4, byteorder="little"))
                    g.write(iat_size.to_bytes(4, byteorder="little"))
                last_addr = fill_iat(g, count_dll, dll_list, new_thunkra, last_sec, api_list)

                #instruction
                g.seek(pesig + offep, os.SEEK_SET)
                g.write(calc_vaddr(last_addr, last_sec).to_bytes(4, byteorder="little"))
                new_thunkra = last_addr
                g.seek(new_thunkra, os.SEEK_SET)
                g.write(b'\x50')
                new_thunkra += 1
                if packer == "PEtite":
                    g.write(b'\x54')
                    g.write(b'\x68')
                    g.write((0x40).to_bytes(4, byteorder="little"))
                    g.write(b'\x68')
                    g.write(size_image.to_bytes(4, byteorder="little"))
                    g.write(b'\x68')
                    g.write(image_base.to_bytes(4, byteorder="little"))
                    g.write(b'\xff\x15')
                    g.write((image_base + vpadr).to_bytes(4, byteorder="little"))
                    new_thunkra += 22
                for dll in dll_list:
                    if dll['num_of_api'] == 0:
                        continue
                    iat_vaddr = image_base + calc_vaddr(dll['new_thunkra'], last_sec)
                    iat_old = image_base + dll['thunkva']
                    for i in range(dll['num_of_api']):
                        g.write(b'\xa1')
                        g.write(iat_vaddr.to_bytes(4, byteorder="little"))
                        g.write(b'\xa3')
                        g.write(iat_old.to_bytes(4, byteorder="little"))
                        iat_vaddr += 4
                        iat_old += 4
                        new_thunkra += 10
                if packer == "PEtite":
                    g.write(b'\xb8')
                    g.write(epva.to_bytes(4, byteorder="little"))
                    g.write(b'\xa3')
                    g.write((image_base + pesig + offep).to_bytes(4, byteorder="little"))
                    new_thunkra += 10
                #g.write(b'\xb8')
                #g.write(addr.to_bytes(4, byteorder="little"))
                #g.write(b'\xa3')
                #g.write((image_base + pesig + impdir_addr).to_bytes(4, byteorder="little"))
                #new_thunkra += 10
                #g.write(b'\xb8')
                #g.write(oldimpsiz.to_bytes(4, byteorder="little"))
                #g.write(b'\xa3')
                #g.write((image_base + pesig + impdir_size).to_bytes(4, byteorder="little"))
                #new_thunkra += 10
                new_thunkra += 6
                g.write(b'\x58')
                g.write(b'\xe9')
                g.write((epva - calc_vaddr(new_thunkra, last_sec)).to_bytes(4, byteorder="little", signed=True))
                last_addr = new_thunkra
                #instruction

                f.seek(pesig + pos_align, os.SEEK_SET)
                data = f.read(4)
                sec_align = int.from_bytes(data, "little")
                data = f.read(4)
                file_align = int.from_bytes(data, "little")
                lsec_size = last_addr - last_sec['secra']
                lsec_vsize = - (- lsec_size // sec_align) * sec_align
                lsec_rsize = - (- lsec_size // file_align) * file_align
                if last_sec['secva'] + lsec_vsize > size_image:
                    g.seek(pesig + sizimg_addr, os.SEEK_SET)
                    g.write((last_sec['secva'] + lsec_vsize).to_bytes(4, byteorder="little"))
                if lsec_vsize > last_sec['secsz']:
                    g.seek(offsec + 40 * sec_ofst + 8, os.SEEK_SET)
                    g.write(lsec_vsize.to_bytes(4, byteorder="little"))
                if lsec_rsize > last_sec['secrs']:
                    g.seek(offsec + 40 * sec_ofst + 16, os.SEEK_SET)
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
    if os.path.isdir(os.path.join(dst, p)):
        shutil.rmtree(os.path.join(dst, p))

plist = pexist

for p in plist:
    if not os.path.isdir(os.path.join(dst, p)):
        os.mkdir(os.path.join(dst, p))
    if p != "WinUpack":
        modify_pe(src, dst, p)
