#pip install pyaes
#pip install pbkdf2
#pip install pycryptodome
import hashlib
from Crypto.Hash import keccak

def decrypt_key(pwd, kdfparams):
    #解密的过程调这个script就行
    dec_key = hashlib.scrypt(bytes(pwd, 'utf-8'), salt=bytes.fromhex(kdfparams['salt']), n=kdfparams['n'], r=kdfparams['r'], p=kdfparams['p'], maxmem=2000000000, dklen=kdfparams['dklen'])
    return dec_key


def verify_key(dec_key, ciphertext, mac):
    #用dec_key去加密一下ciphertext，如果和mac一样则证明是对的
    validate = dec_key[16:] + bytes.fromhex(ciphertext)
    keccak_hash=keccak.new(digest_bits=256)
    keccak_hash.update(validate)
    print(keccak_hash.hexdigest())
    if keccak_hash.hexdigest() == mac:
        return True
    return False

kdfparams={
         "dklen":32,
         "n":65536,
         "p":1,
         "r":8,
         "salt":"592ac5a6690e7f14a28ba5b9a023e29fa702c094cff0f78cac78d429ab95d6a1"
      }
pwd = '密码？'
ciphertext = "2c9ed7199f4d54871187e681133f41a3c8b064a76131465cbcd3db6ec5c3a29d"
mac = "f3eb4036ccd10387dc71178a4cde4fc0612924f97d3f5a52b4f7b9cbcaea0617"

my_key = decrypt_key(pwd, kdfparams)
if verify_key(my_key, ciphertext, mac):
    print('BINGO!恭喜恭喜。')
else:
    print('WRONG.再试试吧。')
