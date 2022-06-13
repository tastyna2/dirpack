import time
import pefile
import json
import hashlib
import os
import subprocess
import yara
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV
from sklearn.metrics import confusion_matrix, accuracy_score, recall_score, precision_score

packer = ["ASPack", "BeRoEXEPacker", "FSG", "JDPack", "MEW", "MPRESS", "Molebox", "NSPack",
    "Neolite", "PECompact", "PEtite", "Packman", "RLPack", "UPX", "WinUpack", "Yoda's Protector",
    "Yoda's Crypter", "eXpressor", "exe32pack"]

def is_pe_file(path):
    rule = yara.compile(
        source="rule pe { condition: uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 }"
    )

    is_pe_file_value = rule.match(path) != []
    return is_pe_file_value

def make_statistical_data(cwd, dir, idlabel):
    n = 256
    f_array = np.empty((0, 4+256))
    l_array = np.empty(0)
    files = os.listdir(os.path.join(cwd, dir))
    files.sort()
    for name in files:
        path = os.path.join(cwd, dir, name)
        if not is_pe_file(path):
            continue
        binary = pefile.PE(path)
        mxmean = 0
        for section in binary.sections:
            offset = 0
            data = section.get_data()
            lgh = len(data) - n + 1
            if lgh < 1:
                lgh = 1
            H = np.zeros(lgh)
            while offset < lgh:
                wndw = list(data[offset:offset+n])
                b = np.bincount(wndw, minlength=256)
                bsum = b.sum()
                if bsum == 0:
                    bsum = 1
                p = b.astype(float) / bsum
                wh = np.where(b)[0]
                H[offset] = np.sum(-p[wh] * np.log2(p[wh]))
                offset+=1
            if mxmean < H.mean():
                mxmean = H.mean()
                entropy = H
                freq = np.bincount(list(data.rstrip(b'\x00')), minlength=256)
        freqsum = freq.sum()
        ratio = freq.astype(float) / freqsum
        feature_vector = np.hstack([entropy.std(), mxmean, entropy.max(), entropy.min(), ratio])
        f_array = np.vstack([f_array, feature_vector])
        l_array = np.hstack([l_array, idlabel])
    return f_array, l_array

tmp = []

for p in packer:
    if os.path.isdir(os.path.join('.', p)):
        tmp.append(p)

packer = tmp

if os.path.isfile('./entsec.npy') and os.path.isfile('./entsec_label.npy'):
    X = np.load('entsec.npy')
    Y = np.load('entsec_label.npy')
else:
    X, Y = make_statistical_data('.', 'Notpacked', 0)
    idx = 1
    for p in packer:
        _X, _Y = make_statistical_data('.', p, idx)
        X = np.vstack([X, _X])
        Y = np.hstack([Y, _Y])
        idx += 1
    np.save('entsec', X)
    np.save('entsec_label', Y)

X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.3, stratify=Y, random_state=0)

parameters = {
    'n_estimators' :[300, 600, 900],
    'max_depth' :[60, 90, 150, 200],
    'min_samples_leaf': [1],
    'min_samples_split': [2]
}

clf = GridSearchCV(estimator=RandomForestClassifier(), param_grid=parameters, cv=5, iid=False)
start = time.perf_counter()
clf.fit(X_train, Y_train)
end = time.perf_counter()
print('rf_entsec: ' + str(end - start))

print("Best parameters set found on development set: %s" % clf.best_params_)

best = clf.best_estimator_
Y_pred = best.predict(X_test)
print(confusion_matrix(Y_test, Y_pred))
print(accuracy_score(Y_test, Y_pred))
print(recall_score(Y_test, Y_pred, average=None))
print(precision_score(Y_test, Y_pred, average=None))

