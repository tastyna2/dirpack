import lief
import json
import hashlib
import os
import subprocess
import yara

packer = ["ASPack", "BeRoEXEPacker", "FSG", "JDPack", "MEW", "MPRESS", "Molebox", "NSPack",
    "Neolite", "PECompact", "PEtite", "Packman", "RLPack", "UPX", "WinUpack", "Yoda's Protector",
    "Yoda's Crypter", "eXpressor", "exe32pack"]

def is_pe_file(path):
    rule = yara.compile(
        source="rule pe { condition: uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 }"
    )

    is_pe_file_value = rule.match(path) != []
    return is_pe_file_value

def count_pe(cwd, dir):
    files = os.listdir(os.path.join(cwd, dir))
    files.sort()
    count = 0
    for name in files:
        path = os.path.join(cwd, dir, name)
        if not is_pe_file(path):
            continue
        count += 1
    return count


tmp = []
for p in packer:
    if os.path.isdir(os.path.join('.', p)):
        tmp.append(p)

packer = tmp

print('notpacked:')
print(count_pe('.', 'Notpacked'))
num = 0
for p in packer:
    print(p + ':')
    eachnum = count_pe('.', p)
    print(eachnum)
    num += eachnum

print('packed:')
print(num)
