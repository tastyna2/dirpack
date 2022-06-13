import hashlib
import os
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

def delete_exe(dir):
        files = os.listdir(os.path.join('.', dir))
        files.sort()
        for name in files:
            src = os.path.join('.', 'Notpacked', name)
            dst = os.path.join('.', dir, name)
            with open(dst, 'rb') as d:
                sample = d.read()
                dst_hash = hashlib.sha256(sample).hexdigest()
            with open(src, 'rb') as s:
                sample = s.read()
                src_hash = hashlib.sha256(sample).hexdigest()
            if dst_hash == src_hash:
                os.remove(dst)
                print(dst)

for p in packer:
    if os.path.isdir(os.path.join('.', p)):
        delete_exe(p)
