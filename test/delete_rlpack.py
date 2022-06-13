import os

WD = '/home/cuckoo/PackDataset'
nonpack = 'Notpacked'
rlpack = 'RLPack'

path = os.path.join(WD, rlpack)
bad_file = []
files = os.listdir(path)
files.sort()
for name in files:
    packed_size = os.stat(os.path.join(WD, rlpack, name)).st_size
    nonpack_sz = os.stat(os.path.join(WD, nonpack, name)).st_size
    if packed_size == nonpack_sz:
        os.remove(os.path.join(WD, rlpack, name))
        bad_file.append(name)

with open('bad_pe.txt', mode='w') as f:
    f.write('\n'.join(bad_file))
