import hashlib
from os import listdir
from os import walk
import os

import sys
# antivirus 

if len(sys.argv) != 4:
	print("Invalid args. required signature database, subdir to scan and quarantine dir")
	print("py antivirus.py ./Signature.DAT ./toscan ./quarantine")
	exit()

signatureDB = open(sys.argv[1])

md5signs = []
sha1signs = []
strings = []

for line in signatureDB:
	if len(str(line[:-2])) == 32:
		md5signs.append(line[:-2])
	elif len(str(line[:-2])) == 40:
		sha1signs.append(line[:-2])
	else:
		strings.append(line[:-2])

f = []

for(path, dirs, files) in walk(sys.argv[2]):
	# print(path, files)
	for f in files:
		if path + "/" + f != sys.argv[1]:
			# print("file " + path+"/"+f)
			f1 = open(path+"/"+f)
			data = f1.read()
			md5sum = hashlib.md5()
			sha1sum = hashlib.sha1()
			md5sum.update(data)
			sha1sum.update(data)
			# print md5sum.hexdigest()
			# print sha1sum.hexdigest()

			infected = False

			if md5sum.hexdigest().upper() in md5signs or sha1sum.hexdigest().upper() in sha1signs:
				infected = True 

			for s in strings:
				if s in data:
					infected = True

			if infected:		
				print("Warning : infected file " + path + "/" + f)
				os.rename(path + "/" + f, sys.argv[3] + "/" + f)

			f1.close()



