from Crypto.Cipher import DES
from Crypto.Cipher import ARC4

key = b'12345678'
des = DES.new(key)
arc4 = ARC4.new(key)
