import hashlib

data = "sensitive-data"

md5_hash = hashlib.md5(data.encode())

sha1_hash = hashlib.sha1(data.encode())