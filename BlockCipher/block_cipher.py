from enum import Enum
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import urllib.parse


class MODES_NUM(Enum):
    ECB = 0
    CBC = 1

def PKCS7_padding(data: bytes, block_size: int) -> bytes:
    # implementation of PKCS#7 padding
    padding = block_size - len(data) % block_size
    return data + bytes([padding] * padding)

def PKCS7_unpadding(data: bytes) -> bytes:
    padding_len = data[-1]
    if padding_len < 1 or padding_len > 16:
        raise ValueError("Invalid padding length")
    if data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Invalid padding bytes")
    return data[:-padding_len]

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

            encrypted_bmp = header + self.encrypt(plaintext, key)

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

        # using PKCS7 padding to to account ofr plaintexts that are not an integral size of AES's block size
        padded_plaintext = PKCS7_padding(plaintext, 16)
        cipher = AES.new(key, AES.MODE_ECB)

        full_cipher_text = b''

        for i in range(0, len(padded_plaintext), 16):
            # encrypt each block of plaintext using the AES cipher
            cipher_text = cipher.encrypt(padded_plaintext[i:i+16])
            full_cipher_text += cipher_text

        return full_cipher_text
    
    def xor_bytes(self, byte_str1: bytes, byte_str2: bytes) -> bytes:
        return bytes(a ^ b for a, b in zip(byte_str1, byte_str2))
    
    def cbc_encrypt(self, plaintext: bytes, key: bytes) -> bytes:
        padded_plaintext = PKCS7_padding(plaintext, 16)
        cipher = AES.new(key, AES.MODE_ECB)
        iv = get_random_bytes(16)

        previous_block = iv
        encrypted_data = iv  # Include IV at the beginning of the encrypted data

        for i in range(0, len(padded_plaintext), 16):
            # XOR the plaintext with the previous ciphertext
            block = padded_plaintext[i:i+16]
            block = self.xor_bytes(block, previous_block)
            encrypted_block = cipher.encrypt(block)
            encrypted_data += encrypted_block
            previous_block = encrypted_block

        return encrypted_data
    
    
class Task2:
    def __init__(self, user_input: str, key: bytes, admin: bool = False):
        self.user_input = user_input
        self.key = key
        self.admin = admin

    def url_encode(self, string: str) -> str:
        return urllib.parse.quote(string)

    def url_decode(self, string: str) -> str:
        return urllib.parse.unquote(string)

    def submit(self):
        cbc_encryption = Task1('CBC')

        padded_user_input = PKCS7_padding(self.user_input.encode(encoding="utf-8"), 16)
        encrypted_msg = cbc_encryption.encrypt(padded_user_input, self.key)

        encoded_string = f'userid=456;userdata={encrypted_msg.hex()};session-id=31337'
        encoded_string = self.url_encode(encoded_string)
        if self.admin:
            encoded_string = encoded_string + ";admin=true"
        print("Encoded string:", encoded_string)
        return encoded_string

    def verify(self, ciphertext: str):
        cipher = AES.new(self.key, AES.MODE_CBC)
        decoded_string = self.url_decode(ciphertext)

        find_admin = decoded_string.find("admin=true")
        start_index = decoded_string.find("userdata=") + len('userdata=')
        end_index = decoded_string.find(";session-id")
        encoded_user_data = decoded_string[start_index:end_index]

        user_data = bytes.fromhex(encoded_user_data)

        iv = user_data[:16]
        encrypted_data = user_data[16:]

        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(encrypted_data)
        try:
            plaintext = PKCS7_unpadding(decrypted_data)
            print("Message:", plaintext.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as e:
            print("Error during decryption or unpadding:", str(e))

        return find_admin != -1


if __name__ == '__main__':
    task_ecb = Task1('ECB')
    task_cbc = Task1('CBC')



    aes_key = get_random_bytes(16)

    task_ecb.encrypt_image('./images/cp-logo.bmp', aes_key)
    task_ecb.encrypt_image('./images/mustang.bmp', aes_key)

    task_cbc.encrypt_image('./images/cp-logo.bmp', aes_key)
    task_cbc.encrypt_image('./images/mustang.bmp', aes_key)




    task_2 = Task2("You're the man now, dog", aes_key)
    encoded_string = task_2.submit()
    print(task_2.verify(encoded_string))