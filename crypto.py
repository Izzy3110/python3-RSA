import base64
import random
import string
import os
import time
import uuid

from datetime import datetime
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


class CryptoManager(object):
    key_passphrase = None
    key_filename = None
    key_folder_abspath = None

    def __init__(self, key_size=None, key_filename=None, key_passphrase=None, clear=None):

        if key_passphrase is None:
            self.key_passphrase = "mykeyPass"
        else:
            self.key_passphrase = key_passphrase

        if key_filename is None:
            self.key_filename = "mykey"
        else:
            self.key_filename = key_filename

        self.key_folder_abspath = os.path.join(os.path.dirname(__file__), os.path.dirname(self.key_filename))

        if clear is not None and clear is True:
            self.clear_keys_in_dir(self.key_folder_abspath)

        if key_size is None:
            self.key_size = 1024
        else:
            self.key_size = key_size

        self.key = self.import_key()

        start_t = time.time()
        input_str = "This is a secret test-string. Helooooooooooooooooooo"

        encrypted_ = self.encrypt_string(input_str)
        decrypted_ = self.decrypt_string(encrypted_)

        # encrypted_b64 = base64.b64encode(encrypted_).decode("utf-8").split("=")[0]
        # decrypted_base64 = self.decrypt_string(base64.b64decode(encrypted_b64 + "="))

        end_t = time.time()
        elapsed_ = end_t - start_t

        ms_ = int(float(str(elapsed_)[:5]) * 1000)
        unit_ = "ms"
        if ms_ >= 1000:
            ms_ = float(ms_) / 1000
            unit_ = "seconds"

        print("# in-data   : " + str(len(input_str.encode("utf-8"))) + " Bytes")
        print("# in-data   : " + str(len(encrypted_)) + " Bytes")
        print("# out       : " + str(decrypted_))
        print("# processed : " + str(ms_) + " "+unit_)

    def generate_rsa_key(self):
        start_t = time.time()
        if not os.path.isfile(self.key_filename):
            key_ = RSA.generate(self.key_size)
            with open(self.key_filename+".pem", 'wb') as privatekey_file:
                privatekey_file.write(key_.export_key('PEM', passphrase=self.key_passphrase))
                privatekey_file.close()

            with open(self.key_filename+".pem.pub", "wb") as publickey_f:
                publickey_f.write(key_.publickey().export_key("PEM"))
                publickey_f.close()

            with open(self.key_filename+".OpenSSH.pub", "wb") as publickey_f:
                publickey_f.write(key_.publickey().export_key("OpenSSH", passphrase=self.key_passphrase))
                publickey_f.close()
            end_t = time.time()
            elapsed_ = end_t - start_t
            ms_ = int(float(str(elapsed_)[:5]) * 1000)
            unit_ = "ms"
            if ms_ >= 1000:
                ms_ = float(ms_) / 1000
                unit_ = "seconds"

            print("# generated : " + str(ms_) + " " + unit_)

            return self.import_key()

    def encrypt_string(self, message_to_encrypt):
        start_t = time.time()
        if self.key is None:
            self.key = self.import_key()
        encrypted = PKCS1_OAEP.new(self.key.publickey()).encrypt(message_to_encrypt.encode("utf-8"))
        end_t = time.time()
        elapsed_ = end_t - start_t
        ms_ = int(float(str(elapsed_)[:5]) * 1000)
        unit_ = "ms"
        if ms_ >= 1000:
            ms_ = float(ms_) / 1000
            unit_ = "seconds"

        print("# encrypted : " + str(ms_) + " " + unit_)
        return encrypted

    def decrypt_string(self, encrypted_message):
        start_t = time.time()
        decrypted = PKCS1_OAEP.new(self.key).decrypt(encrypted_message)

        end_t = time.time()
        elapsed_ = end_t - start_t
        ms_ = int(float(str(elapsed_)[:5]) * 1000)
        unit_ = "ms"
        if ms_ >= 1000:
            ms_ = float(ms_) / 1000
            unit_ = "seconds"

        print("# decrypted : " + str(ms_) + " " + unit_)

        return decrypted.decode("utf-8")

    @staticmethod
    def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
        return ''.join(random.choice(chars) for _ in range(size))

    def import_key(self):
        if os.path.isfile(self.key_filename+".pem"):
            if self.key_passphrase is not None:
                return RSA.import_key(open(self.key_filename+".pem").read(), passphrase=self.key_passphrase)
            else:
                return RSA.import_key(open(self.key_filename+".pem").read())
        else:
            self.key = self.generate_rsa_key()

    @staticmethod
    def clear_keys_in_dir(folder_abspath):
        if os.path.isdir(folder_abspath):
            for f in os.listdir(folder_abspath):
                print("removing: " + f)
                if os.path.isfile(os.path.join(folder_abspath, f)):
                    os.remove(os.path.join(folder_abspath, f))

    @staticmethod
    def generate_key_filename(prefix, key_size):
        return prefix + "-" + str(key_size) + "-" + datetime.now().strftime("%Y%m%d-%H%M%S")

    @staticmethod
    def gen_uuid():
        return str(uuid.uuid4())


if __name__ == '__main__':
    if not os.path.isdir("keys"):
        os.mkdir("keys")

    username_ = "izzy"
    key_size_ = 1024
    key_prefix_ = "_".join([username_, CryptoManager.gen_uuid()])
    key_filename_ = CryptoManager.generate_key_filename(key_prefix_, key_size_)
    print("new_file: "+key_filename_)

    cry_ = CryptoManager(
        key_filename=os.path.join("keys", key_filename_),
        key_size=key_size_,
        clear=True
    )
