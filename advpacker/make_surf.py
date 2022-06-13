import shutil
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

def get_strings(path):
    result = (
        subprocess.run(["strings", path], stdout=subprocess.PIPE, check=True)
        .stdout.decode("utf-8")
        .split("\n")[:-1]
    )
    return result

def make_json_data(cwd, dir):
    with open(os.path.join('.', 'surf_data' , dir + '.jsonl'), mode='w') as f:
        files = os.listdir(os.path.join(cwd, dir))
        files.sort()
        for name in files:
            path = os.path.join(cwd, dir, name)
            if not is_pe_file(path):
                continue
            data = dict()
            data['file_size'] = os.stat(path).st_size
            data['lief'] = json.loads(lief.to_json(lief.PE.parse(path)))
            data['name'] = name
            with open(path, 'rb') as b:
                sample = b.read()
                data['id'] = hashlib.sha256(sample).hexdigest()
            data['strings'] = get_strings(path)
            data['packer'] = dir
            if dir == 'Notpacked':
                data['packed'] = 0
            else:
                data['packed'] = 1
            f.write(json.dumps(data) + '\n')

if not os.path.isdir('./surf_data'):
    os.mkdir('surf_data')

for p in packer:
    if os.path.isdir(os.path.join('.', p)):
        make_json_data('.', p)
