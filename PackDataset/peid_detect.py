import json
import sys
import os
import subprocess

packer = ["ASPack", "BeRoEXEPacker", "FSG", "JDPack", "MEW", "MPRESS", "Molebox", "NSPack",
    "Neolite", "PECompact", "PEtite", "Packman", "RLPack", "UPX", "WinUpack", "Yoda's Protector",
    "Yoda's Crypter", "eXpressor", "exe32pack"]

def show_type_estimation_performance(results):
    n_total = sum(i['n_samples'] for i in results.values())
    n_purely_detected = sum(
        i['detectable']['purely'] + i['detectable']['excessively']
        if i['packed']
        else i['non_detectable']['purely']
        for i in results.values()
    )
    print("Categorical Accuracy: ", n_purely_detected / n_total)

def parse_peid_data(dir):
    with open(os.path.join('.', 'peid_data' , dir + '.jsonl'), mode='r') as f:
        n_samples_failed = 0
        n_samples_scanned = 0
        purely_detected_as_packed = 0
        excessively_detected_as_packed = 0
        purely_detected_as_non_packed = 0
        non_packed_but_excessively_detected_as_packed = 0
        for line in f:
            data = json.loads(line)
            if "PEiD" not in data['peid'] or "detectable" not in data:
                print(f"Scan failed sample", data["name"], file=sys.stderr)
                n_samples_failed += 1
                continue

            n_samples_scanned += 1
            if data['detectable']:
                if len(data['peid']['PEiD']) > 1:
                    excessively_detected_as_packed += 1
                else:
                    purely_detected_as_packed += 1
            else:
                if len(data['peid']['PEiD']) <= 0:
                    purely_detected_as_non_packed += 1
                else:
                    non_packed_but_excessively_detected_as_packed += 1

    if dir == 'Notpacked':
        packed = False
    else:
        packed = True

    result = {
        "packed": packed,
        "n_samples": n_samples_scanned,
        "detectable": {
            "purely": purely_detected_as_packed,
            "excessively": excessively_detected_as_packed,
        },
        "non_detectable": {
            "purely": purely_detected_as_non_packed,
            "excessively": non_packed_but_excessively_detected_as_packed,
        },
    }

    return result

results = dict()

results['Notpacked'] = parse_peid_data('Notpacked')
for p in packer:
    if os.path.isdir(os.path.join('.', p)):
        results[p] = parse_peid_data(p)

show_type_estimation_performance(results)
