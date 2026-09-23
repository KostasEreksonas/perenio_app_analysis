#!/usr/bin/env python3

import base64

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha1, pbkdf2_hmac

class LocalAESCipher(object):
    def __init__(self, key, salt, iv, digest):
        self.key = key.encode('utf-8')
        self.salt = salt.encode('utf-8')
        self.iv = iv
        self.digest = digest

    def hashTheKey(self):
        sha1Hash = sha1(self.key).digest()

        b64 = base64.b64encode(sha1Hash).decode('utf-8')
        b64 = b64.rstrip('=') + '\n' # Account for Android's Base64.NO_PADDING that emits a trailing newline 
    
        return b64.encode('utf-8')

    def getSecretKey(self, password, iterations, keyLength):
        return pbkdf2_hmac(self.digest, password, self.salt, iterations, keyLength)

    def encrypt(self, secretKey, plaintext):
        cipher = AES.new(secretKey, AES.MODE_CBC, self.iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        return base64.b64encode(ciphertext)

    def decrypt(self, secretKey, ciphertext):
        cipher = AES.new(secretKey, AES.MODE_CBC, self.iv)
        decoded = base64.b64decode(ciphertext)
        plaintext = unpad(cipher.decrypt(decoded), AES.block_size)

        return plaintext.decode('utf-8')


def main():
    cipherObject = LocalAESCipher("A45BE7EF0543D36B4F68DvD3EF4013D4", "BDBA982FAF389694", b'\x00' * 16, 'sha1')
    password = cipherObject.hashTheKey()
    secretKey = cipherObject.getSecretKey(password, 1, 16)
    encrypted = "fDVKEevP86vks8HDWcsWwUoWhYUauso/2AssuLobQj85iUTBCLK6YJbUP7AxfFwXHjKn3F3URNgh/2SvLbPOPqS3wos0B9h8m/Q9jtfCVvEt3TqiLY0dSeff12q/2BmDRKpBQYHFeO+F8UKtMuNdoA==\n"
    plaintext = b"{\"commonPrefs\":{\"display_rate_us_after\":0,\"permission_event_severity\":\"event\"},\"devicePrefs\":{}}"

    print(f"Key: {cipherObject.key.decode('utf-8')}")
    print(f"Salt: {cipherObject.salt.decode('utf-8')}")
    print(f"IV: {cipherObject.iv.hex()}")
    print(f"PBKDF2 digest algorithm: {cipherObject.digest}")
    print(f"Secret key: {secretKey.hex()}")
    print(f"Encrypted: {encrypted}\nPlain text: {cipherObject.decrypt(secretKey, encrypted)}")
    print(f"Plain text: {plaintext}\nEncrypted: {cipherObject.encrypt(secretKey, plaintext)}")

if __name__ == "__main__":
    main()