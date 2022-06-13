import json
import hashlib
import os
import subprocess
import yara
from pypeid import PEiDScanner

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

def make_peid_data(cwd, dir):
    with open(os.path.join('.', 'peid_data' , dir + '.jsonl'), mode='w') as f:
        files = os.listdir(os.path.join(cwd, dir))
        files.sort()
        for name in files:
            path = os.path.join(cwd, dir, name)
            if not is_pe_file(path):
                continue
            data = dict()
            scanner = PEiDScanner()
            data['peid'] = scanner.scan_file(path)
            label = dir
            label = label.replace("Yoda's ", "yodas_")
            data['detectable'] = False
            if "PEiD" in data['peid']:
                for peid in data['peid']['PEiD']:
                    if label.lower() in peid.lower():
                        data['detectable'] = True
                        break
            data['name'] = name
            with open(path, 'rb') as b:
                sample = b.read()
                data['id'] = hashlib.sha256(sample).hexdigest()
            data['packer'] = dir
            if dir == 'Notpacked':
                data['packed'] = 0
            else:
                data['packed'] = 1
            f.write(json.dumps(data) + '\n')

if not os.path.isdir('./peid_data'):
    os.mkdir('peid_data')

make_peid_data('.', 'Notpacked')
for p in packer:
    if os.path.isdir(os.path.join('.', p)):
        make_peid_data('.', p)
