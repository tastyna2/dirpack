import json
import os
import time
import numpy as np
import pandas as pd
from new_extract import PackedFeatureExtractor
from sklearn.model_selection import train_test_split
from sklearn import preprocessing
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV
from sklearn.metrics import confusion_matrix, accuracy_score, recall_score, precision_score

def split_file(dir):
    files = os.listdir(dir)
    files.sort()
    files = np.array(files)
    idx = np.arange(len(files))
    tridx, tsidx = train_test_split(idx, test_size=0.3, random_state=0)
    return files[tridx], files[tsidx]

def load_surf_info(dir, flist, *args):
    extractor = PackedFeatureExtractor()
    f_array = np.empty((0, extractor.dim))
    l_array = np.empty(0)
    count = 0
    print(extractor.dim)
    idpack = dict(zip(args, range(len(args))))
    for pack in args:
        if p == 'Notpacked':
            continue
        fname = os.path.join(dir, 'surf_data', pack + '.jsonl')
        if not os.path.isfile(fname):
            continue
        j = 1

        with open(fname) as f:
            for line in f:
                data = json.loads(line)
                if not data['name'] in flist:
                    continue
                feature_vector = extractor.process_raw_features(data)
                f_array = np.vstack([f_array, feature_vector])
                l_array = np.hstack([l_array, idpack[data['packer']]])
                j += 1
                count += 1

    return f_array, l_array

HD = '/home/cuckoo'
WD = ['PackDataset', 'advpacker']

packer = ["ASPack", "BeRoEXEPacker", "FSG", "JDPack", "MEW", "MPRESS", "Molebox", "NSPack",
    "Neolite", "PECompact", "PEtite", "Packman", "RLPack", "UPX", "WinUpack", "Yoda's Protector",
    "Yoda's Crypter", "eXpressor", "exe32pack"]

tmp = []

for p in packer:
    if p == 'WinUpack':
        continue
    if os.path.isfile(os.path.join(HD, WD[0], 'surf_data', p + '.jsonl')):
        tmp.append(p)

packer = tmp

F_train, F_test = split_file('/home/cuckoo/PackDataset/Notpacked')

if os.path.isfile('./idpack.npy') and os.path.isfile('./idpack_label.npy'):
    X = np.load('idpack.npy')
    Y = np.load('idpack_label.npy')
else:
    path = os.path.join(HD, WD[0])
    X_train, Y_train = load_surf_info(path, F_train, *packer)

parameters = {
    'n_estimators' :[300, 600, 900],
    'max_depth' :[60, 90, 150, 200],
    'min_samples_leaf': [1],
    'min_samples_split': [2]
}

clf = GridSearchCV(estimator=RandomForestClassifier(), param_grid=parameters)
clf.fit(X_train, Y_train)

print('\ndos_sname_schr_import')
print("Best parameters set found on development set: %s" % clf.best_params_)

best = clf.best_estimator_
fti = best.feature_importances_
ext = PackedFeatureExtractor()
name = ext.name_strings()
with open('pack_gini.txt', mode='w') as fp:
    for n, ft in sorted(zip(name, fti), key=lambda x: x[1], reverse=True):
        fp.write(n + ' : ' + str(ft) + '\n')

for d in WD:
    path = os.path.join(HD, d)
    X_test, Y_test = load_surf_info(path, F_test, *packer)
    Y_pred = best.predict(X_test)
    cm = confusion_matrix(Y_test, Y_pred, labels=list(range(len(packer))))
    cm = pd.DataFrame(cm, columns=packer, index=packer)
    print(d, ':')
    print(cm.to_markdown())
    print('accuracy : ',accuracy_score(Y_test, Y_pred))
    print('recall : ', recall_score(Y_test, Y_pred, average=None))
    print('precision : ', precision_score(Y_test, Y_pred, average=None))
    print()
