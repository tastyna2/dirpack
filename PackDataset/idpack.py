import json
import os
import time
import numpy as np
from extract import PackedFeatureExtractor
from sklearn.model_selection import train_test_split
from sklearn import preprocessing
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV
from sklearn.metrics import confusion_matrix, accuracy_score, recall_score, precision_score

def load_surf_info(*args):
    extractor = PackedFeatureExtractor()
    f_array = np.empty((0, extractor.dim))
    l_array = np.empty(0)
    count = 0
    print(extractor.dim)
    idpack = dict(zip(args, range(len(args))))
    for pack in args:
        fname = os.path.join('surf_data', pack + '.jsonl')
        j = 1

        with open(fname) as f:
            for line in f:
                data = json.loads(line)
                feature_vector = extractor.process_raw_features(data)
                f_array = np.vstack([f_array, feature_vector])
                l_array = np.hstack([l_array, idpack[data['packer']]])
                j += 1
                count += 1

    return f_array, l_array

packer = ["Notpacked", "ASPack", "BeRoEXEPacker", "FSG", "JDPack", "MEW", "MPRESS", "Molebox",
    "NSPack", "Neolite", "PECompact", "PEtite", "Packman", "RLPack", "UPX", "WinUpack",
    "Yoda's Protector", "Yoda's Crypter", "eXpressor", "exe32pack"]

tmp = []

for p in packer:
    if os.path.isfile(os.path.join('.', 'surf_data', p + '.jsonl')):
        tmp.append(p)

packer = tmp

if os.path.isfile('./idpack.npy') and os.path.isfile('./idpack_label.npy'):
    X = np.load('idpack.npy')
    Y = np.load('idpack_label.npy')
else:
    X, Y = load_surf_info(*packer)
    np.save('idpack', X)
    np.save('idpack_label', Y)

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
print('rf_surf: ' + str(end - start))
print(end - start)

print("Best parameters set found on development set: %s" % clf.best_params_)

best = clf.best_estimator_
fti = best.feature_importances_
ext = PackedFeatureExtractor()
name = ext.name_strings()
with open('pack_gini.txt', mode='w') as fp:
    for n, ft in sorted(zip(name, fti), key=lambda x: x[1], reverse=True):
        fp.write(n + ' : ' + str(ft) + '\n')

Y_pred = best.predict(X_test)
print(confusion_matrix(Y_test, Y_pred))
print(accuracy_score(Y_test, Y_pred))
print(recall_score(Y_test, Y_pred, average=None))
print(precision_score(Y_test, Y_pred, average=None))
