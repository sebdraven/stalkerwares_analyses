from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad
from base64 import b64decode

KEY = b"vallengt"
cipher = DES.new(KEY, DES.MODE_ECB)

def decrypt(b64):
    ct = b64decode(b64)
    pt = cipher.decrypt(ct)
    return unpad(pt, 8).decode()

snpa = "O4MkUWSy2w8l+q9IeEEKmD8bzy/MLGOuO4MkUWSy2w8AGXZGDD1v7oP2Y7eJwWNb913z4+UPlNgQ\no/m0ruse4stmDc+aPJ7hLX3yaN+WuMUKC5YLbFNtkA=="
hwa  = "O4MkUWSy2w/J0RDFuayF5Ews4PV4Ocp8zP7SC0Tqr8tNqvR67gt5eLENzuZr371ILX3yaN+WuMUV\n3d5sswyBFBNI5FtH3kiMb/0dsnsdKtY="

print("SNPA:", decrypt(snpa))
print("HWA :", decrypt(hwa))
