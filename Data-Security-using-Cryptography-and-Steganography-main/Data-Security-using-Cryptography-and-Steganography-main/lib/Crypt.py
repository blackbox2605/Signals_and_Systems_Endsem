from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from lib.TripleDES import triple_des
import rsa
import os
import hashlib
import base64
import logging

class Crypt:
    def __init__(self, key=""):
        self.triple = None
        self.key = key

    @staticmethod
    def pad(s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    @staticmethod
    def triplehash(passw):
        has = hashlib.md5(passw.encode()).hexdigest()
        new = ""
        for i, j in enumerate(has):
            if i % 4 == 0:
                continue
            else:
                new += j
        return new

    def encrypt(self, message, key):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def encrypt_rsa(self, message, pubkey='lib/output/public.pem'):
        f = open(pubkey, 'rb')
        self.key = RSA.importKey(f.read())
        message = rsa.encrypt(message, self.key)
        return message

    def decrypt_rsa(self, message, prikey='lib/output/private.pem'):
        with open(prikey, 'rb') as f:
            private_key = RSA.importKey(f.read())
        cipher_rsa = PKCS1_OAEP.new(private_key)
        decrypted_message = cipher_rsa.decrypt(message)
        return decrypted_message

    def encrypt_file(self, file_name):
        try:
            with open(file_name, 'rb') as fo:
                plaintext = fo.read()
        except FileNotFoundError:
            return
        if len(plaintext) < 245:
            keyF = input("Public Key file location for RSA [default - lib/output/public.pem]: ")
            if keyF == '':
                enc = self.encrypt_rsa(plaintext)
            else:
                enc = self.encrypt_rsa(plaintext, keyF)
        else:
            print("File too large, RSA not used!")
            enc = plaintext

        passW = input(f"Set password for [{file_name}]: ")
        self.key = hashlib.shake_128(passW.encode("utf-8")).hexdigest(16)
        enc = self.encrypt(enc, self.key)

        self.key = self.triplehash(passW)
        self.triple = triple_des(self.key)
        enc = self.triple.encrypt(enc)

        newF = file_name + ".enc"
        with open(newF, 'wb') as fo:
            fo.write(enc)
        print("\nFile Encrypted!")
        return newF

    @staticmethod
    def decrypt(ciphertext, key):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def decrypt_file(self, file_name):
        try:
            with open(file_name, 'rb') as fo:
                ciphertext = fo.read()

            passW = input("File password: ")

            # Decrypt the first layer with Triple DES
            self.key = self.triplehash(passW)
            self.triple = triple_des(self.key)
            ciphertext = self.triple.decrypt(ciphertext)

            # Decrypt with AES
            self.key = hashlib.shake_128(passW.encode("utf-8")).hexdigest(16)
            dec = self.decrypt(ciphertext, self.key)

            # Decrypt with RSA if applicable
            keyF = input("Private Key file location for RSA [default - lib/output/private.pem]: ")
            if keyF == '':
                keyF = "lib/output/private.pem"
            try:
                dec1 = self.decrypt_rsa(dec, keyF)
            except (ValueError, TypeError):
                print("Not encrypted using RSA, ignored...")
                dec1 = dec

            # Convert binary data to text format
            try:
                text_content = dec1.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    # Fallback to ISO-8859-1
                    print("UTF-8 decoding failed, trying ISO-8859-1.")
                    text_content = dec1.decode('iso-8859-1')
                except UnicodeDecodeError:
                    # Final fallback to Base64 encoding for readable output
                    print("Decoding failed. Encoding as Base64 for readable output.")
                    text_content = base64.b64encode(dec1).decode('utf-8')

            op_file = file_name[:-4] + "_decrypted.txt"

            # Writing text content as human-readable output
            with open(op_file, 'w', encoding='utf-8') as fo:
                fo.write(text_content)

            os.remove(file_name)
            print("File fully Decrypted!!!")
            print(f"Output available at: {op_file}")
        except ValueError as e:
            logging.error(f"Error during decryption: {e}")
            print(f"Error during decryption: {e} - likely due to an incorrect key or corrupted data.")
        except Exception as e:
            logging.error(f"Error during decryption: {e}")
            print(f"Error during decryption: {e}")

    @staticmethod
    def getAllFiles():
        dir_path = os.path.dirname(os.path.realpath(__file__))
        dirs = []
        for dirName, subdirList, fileList in os.walk(dir_path):
            for fname in fileList:
                dirs.append(dirName + "/" + fname)
        return dirs

    def encrypt_all_files(self):
        dirs = self.getAllFiles()
        for file_name in dirs:
            self.encrypt_file(file_name)

    def decrypt_all_files(self):
        dirs = self.getAllFiles()
        for file_name in dirs:
            self.decrypt_file(file_name)

def aes_encrypt_file(input_file, output_file, key, key_size):
    try:
        cipher = AES.new(key, AES.MODE_EAX)
        with open(input_file, 'rb') as f:
            data = f.read()
        ciphertext, tag = cipher.encrypt_and_digest(data)

        with open(output_file, 'wb') as f_out:
            for x in (cipher.nonce, tag, ciphertext):
                f_out.write(x)
        logging.info(f"File {input_file} has been AES-encrypted with {key_size * 8}-bit key to {output_file}")
        print(f"File {input_file} has been AES-encrypted to {output_file}")
    except Exception as e:
        logging.error(f"Error during AES encryption: {e}")
        print(f"Error during encryption: {e}")

def aes_decrypt_file(input_file, output_file, key):
    try:
        with open(input_file, 'rb') as f:
            nonce, tag, ciphertext = [f.read(x) for x in (16, 16, -1)]

        if len(key) not in {16, 24, 32}:
            raise ValueError("Invalid AES key length")

        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)

        with open(output_file, 'wb') as f_out:
            f_out.write(data)
        logging.info(f"File {input_file} has been AES-decrypted to {output_file}")
        print(f"File {input_file} has been decrypted to {output_file}")
    except ValueError as e:
        logging.error(f"Error during AES decryption: {e}")
        print(f"Error during decryption: {e} - likely due to an incorrect key or corrupted data.")
    except Exception as e:
        logging.error(f"Error during AES decryption: {e}")
        print(f"Error during decryption: {e}")
