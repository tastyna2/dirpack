import os

dir = "/home/cuckoo/test/text.txt"

with open(dir, mode="r") as f, open(dir, mode="r+") as g:
    data = f.read(4)
    g.seek(0, os.SEEK_END)
    g.write(data)
