from enum import Enum
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

IV = get_random_bytes(128)

class MODES_NUM(Enum):
    ECB = 0
    CBC = 1

def PKCS7_padding(data: bytes, block_size: int) -> bytes:
    # implementation of PKCS#7 padding
    padding = block_size - len(data) % block_size
    return data + bytes([padding] * padding)

class Task1:
    def __init__(self, modes: str):
        self.modes = MODES_NUM[modes]

    def encrypt_image(self, input_file: str, key: bytes):
        plain_text_file = input_file
        file_name = os.path.basename(input_file)
        output_directory = "./ciphertext"
        output_file = os.path.join(output_directory, file_name + f"_{self.modes.name}_encrypted.bmp")

        with open(plain_text_file, 'rb') as file:
            bmp_data = file.read()
            header = bmp_data[:54] 
            plaintext = bmp_data[54:]

            # using PKCS7 padding to to account ofr plaintexts that are not an integral size of AES's block size
            padded_plaintext = PKCS7_padding(plaintext, 128)
            encrypted_bmp = header + self.encrypt(padded_plaintext, key)

            # Write the encrypted text to a file
            if not os.path.exists(output_directory):
                os.makedirs(output_directory)

            # write to output file
            with open(output_file, 'wb') as file:
                file.write(encrypted_bmp)
                print(f"Encrypted text has been written to {output_file}")

    def encrypt(self, plaintext: bytes, key: bytes) -> bytes:
        if self.modes == MODES_NUM.ECB:
            return self.ecb_encrypt(plaintext, key)
            
        
        elif self.modes == MODES_NUM.CBC:
            return self.cbc_encrypt(plaintext, key)
        
        else:
            raise Exception('Invalid mode')
        
    def ecb_encrypt(self, plaintext: bytes, key: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_ECB)

        full_cipher_text = b''

        for i in range(0, len(plaintext), 128):
            # encrypt each block of plaintext using the AES cipher
            cipher_text = cipher.encrypt(plaintext[i:i+128])
            full_cipher_text += cipher_text

        return full_cipher_text
    
    def xor_bytes(self, byte_str1: bytes, byte_str2: bytes) -> bytes:
        return bytes(a ^ b for a, b in zip(byte_str1, byte_str2))
    
    def cbc_encrypt(self, plaintext: bytes, key: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_CBC)

        full_cipher_text = b''

        initial_plain_text = plaintext[0:128] 
        cipher_text = self.xor_bytes(initial_plain_text, IV)
        full_cipher_text += cipher.encrypt(cipher_text)

        for i in range(128, len(plaintext), 128):
            # XOR the plaintext with the previous ciphertext
            plain_text_used_for_encryption = self.xor_bytes(cipher_text, plaintext[i:i+128])
            cipher_text = cipher.encrypt(plain_text_used_for_encryption) # used to XOR next iteration in CBC
            full_cipher_text += cipher_text

        return full_cipher_text
    
class Task2:
    def __init__(self, user_input: str, key: bytes):
        self.user_input = user_input
        self.key = key

    def url_encode(self, string: str):
        encoded_string = ""
        for char in string:
            if char == ';':
                encoded_string += '%3B'
            elif char == '=':
                encoded_string += '%3D'
            else:
                encoded_string += char
        return encoded_string

    def submit(self):
        cbc_encryption = Task1('CBC')

        padded_user_input = PKCS7_padding(self.user_input.encode(encoding="utf-8"), 128)
        encrypted_msg = cbc_encryption.encrypt(padded_user_input, self.key)

        encoded_string = f'userid=456;userdata={encrypted_msg.hex()};session-id=31337'
        encoded_string = self.url_encode(encoded_string)
        print("Encoded string:", encoded_string)
        return encoded_string

    def verify(self, ciphertext: str):
        print(ciphertext)
        cipher = AES.new(self.key, AES.MODE_CBC)
        start_index = ciphertext.find("userdata%3D") + len('userdata%3D')
        end_index = ciphertext.find("%3Bsession-id")
        encoded_user_data = ciphertext[start_index:end_index]

        # encoded_user_data = ciphertext[ciphertext.find("userdata%3D") + len('userdata%3D') : ciphertext.find("%3Bsession-id")]
        user_data = bytes.fromhex(encoded_user_data)

        print(user_data)
        print(len(user_data))
        print(len(user_data) % 128)
        message = cipher.decrypt(user_data)
        print("Message:", message.decode())


if __name__ == '__main__':
    task_ecb = Task1('ECB')
    task_cbc = Task1('CBC')

    aes_key = get_random_bytes(16)

    # print("IV", IV)

    # task_ecb.encrypt_image('./images/cp-logo.bmp', aes_key)
    # task_ecb.encrypt_image('./images/mustang.bmp', aes_key)

    # task_cbc.encrypt_image('./images/cp-logo.bmp', aes_key)
    # task_cbc.encrypt_image('./images/mustang.bmp', aes_key)

    
    task_2 = Task2("You're the man now, dog", aes_key)
    encoded_string = task_2.submit()
    task_2.verify(encoded_string)