import json
import os
import time
import numpy as np
from extract import PackedFeatureExtractor
from imblearn.under_sampling import RandomUnderSampler

cwd = '/home/cuckoo/PackDataset'

def load_surf_info(*args):
    extractor = PackedFeatureExtractor()
    f_array = np.empty((0, extractor.dim))
    l_array = np.empty(0)
    count = 0
    print(extractor.dim)
    for pack in args:
        fname = os.path.join(cwd, 'surf_data', pack + '.jsonl')
        j = 1

        with open(fname) as f:
            for line in f:
                data = json.loads(line)
                feature_vector = extractor.process_raw_features(data)
                f_array = np.vstack([f_array, feature_vector])
                l_array = np.hstack([l_array, data['packed']])
                j += 1
                count += 1

    return f_array, l_array

packer = ["Notpacked", "ASPack", "BeRoEXEPacker", "FSG", "JDPack", "MEW", "MPRESS", "Molebox",
    "NSPack", "Neolite", "PECompact", "PEtite", "Packman", "RLPack", "UPX", "WinUpack",
    "Yoda's Protector", "Yoda's Crypter", "eXpressor", "exe32pack"]

tmp = []

for p in packer:
    if os.path.isfile(os.path.join(cwd, 'surf_data', p + '.jsonl')):
        tmp.append(p)

packer = tmp

X, Y = load_surf_info(*packer)

print(X.shape)

if not os.path.isfile('./all.npy'):
    np.save('all', X)

if not os.path.isfile('./label.npy'):
    np.save('label', Y)

sampler = RandomUnderSampler(random_state=42)
X_resampled, Y_resampled = sampler.fit_resample(X, Y)

print(len(X_resampled[Y_resampled == 0, 0]))
print(len(X_resampled[Y_resampled == 1, 0]))

if not os.path.isfile('./resamp.npy'):
    np.save('resamp', X_resampled)

if not os.path.isfile('./rslabel.npy'):
    np.save('rslabel', Y_resampled)
