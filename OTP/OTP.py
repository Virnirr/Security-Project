from __future__ import annotations
import os


class Task1:

    # Task #1: Implement a function that performs XOR operation on two strings of the same length
    def xor_strings(self, str1: str, str2: str) -> str:
        if len(str1) != len(str2):
            raise ValueError("Error: The two strings must have the same length.")
        
        result = bytearray(a ^ b for a, b in zip(bytearray(str1, 'utf-8'), bytearray(str2, 'utf-8')))
        return result.hex()


class Task2:

    def xor_bytes(self, byte_str1: bytearray, byte_str2: bytearray) -> bytes:
        return bytes(a ^ b for a, b in zip(byte_str1, byte_str2))

    def xor_encrypt_text(self, input_file: str) -> None:
        plain_text_file = input_file
        file_name = os.path.basename(input_file)
        output_directory = "./ciphertext"
        output_file = os.path.join(output_directory, file_name + "_encrypted.txt")

        # Read the plaintext file
        with open(plain_text_file, 'rb') as file:
            plain_text = file.read()
            print(plain_text)

            # Generate a random key as long as plain_text
            key = os.urandom(len(plain_text))

            print("This is your bit key:", key)
            # Perform XOR operation on the plaintext and the key
            ciphertext = self.xor_bytes(plain_text, key)

            # Write the encrypted text to a file
            if not os.path.exists(output_directory):
                os.makedirs(output_directory)

            with open(output_file, 'wb') as file:
                file.write(ciphertext)
                print(f"Encrypted text has been written to {output_file}")

            # Verify decryption
            self.check_xor_plaintext(ciphertext, plain_text, key)

    def check_xor_plaintext(self, ciphertext: str, plaintext: str, key: str) -> None:
        
        # XOR the ciphertext with the key to verify decryption
        decrypted_text = self.xor_bytes(ciphertext, key)

        # Verify that the decrypted text matches the original plaintext
        if decrypted_text == plaintext:
            print("Decryption successful. The original plaintext has been recovered.")
        else:
            print("Decryption failed. The decrypted text does not match the original plaintext.")

class Task3:

    def xor_bytes(self, byte_str1: bytes, byte_str2: bytes) -> bytes:
        return bytes(a ^ b for a, b in zip(byte_str1, byte_str2))

    def xor_encrypt_image(self, input_file: str) -> None:
        plain_text_file = input_file
        file_name = os.path.basename(input_file)
        output_directory = "./ciphertext"
        output_file = os.path.join(output_directory, file_name + "_encrypted.bmp")


        # Read the plaintext file
        with open(plain_text_file, 'rb') as file:
            bmp_data = file.read()

            header = bmp_data[:54]  # BMP header is typically 54 bytes long so you're able to view your encrypted bmp image
            plaintext = bmp_data[54:]
            # Generate a random key as long as plain_text
            key = os.urandom(len(plaintext))

            # Perform XOR operation on the plaintext and the key
            ciphertext = self.xor_bytes(plaintext, key)

            encrypted_bmp = header + ciphertext

            # Write the encrypted text to a file
            if not os.path.exists(output_directory):
                os.makedirs(output_directory)

            with open(output_file, 'wb') as file:
                file.write(encrypted_bmp)
                print(f"Encrypted text has been written to {output_file}")

            # Verify decryption
            self.check_xor_image(encrypted_bmp, bmp_data, key)

    def check_xor_image(self, encrypted_bmp: bytes, plaintext: bytes, key: bytes) -> None:
        
        # Extract the ciphertext from the encrypted BMP
        ciphertext = encrypted_bmp[54:]

        # XOR the ciphertext with the key to verify decryption
        decrypted_text = self.xor_bytes(ciphertext, key)

        # Verify that the decrypted text matches the original plaintext
        if decrypted_text == plaintext[54:]:
            print("Decryption successful. The original plaintext has been recovered.")
        else:
            print("Decryption failed. The decrypted text does not match the original plaintext.")


class Task4:

    def xor_bytes(self, byte_str1: bytes, byte_str2: bytes) -> bytes:
        return bytes(a ^ b for a, b in zip(byte_str1, byte_str2))

    def xor_encrypt_image(self, input_file1: str, input_file2) -> None:

        file_name = "combined_images"
        output_directory = "./ciphertext"
        output_file = os.path.join(output_directory, file_name + "_encrypted.bmp")


        # Read the plaintext file
        with open(input_file1, 'rb') as file:
            bmp_data = file.read()

            with open(input_file2, 'rb') as file2:

                bmp_data2 = file2.read()

                header = bmp_data[:54]  # BMP header is typically 54 bytes long so you're able to view your encrypted bmp image
                plaintext = bmp_data[54:]
                plaintext2 = bmp_data2[54:]
                # Generate a random key as long as plain_text 
                key = os.urandom(len(plaintext))

                # Perform XOR operation on the plaintext and the key
                ciphertext1 = self.xor_bytes(plaintext, key)
                ciphertext2 = self.xor_bytes(plaintext2, key)

                # xor both ciphertexts to get the final encrypted image (header doesn't matter)
                encrypted_bmp = header + self.xor_bytes(ciphertext1, ciphertext2)

                # Write the encrypted text to a file
                if not os.path.exists(output_directory):
                    os.makedirs(output_directory)

                with open(output_file, 'wb') as file:
                    file.write(encrypted_bmp)
                    print(f"Encrypted text has been written to {output_file}")


if __name__ == "__main__":
    str1 = "Darlin dont you go"
    str2 = "and cut your hair!"

    task1 = Task1()
    print(task1.xor_strings(str1, str2))

    task2 = Task2()
    task2.xor_encrypt_text("./plaintext/somefile.txt")

    task3 = Task3()
    task3.xor_encrypt_image("./image/cp-logo.bmp")
    task3.xor_encrypt_image("./image/mustang.bmp")

    task4 = Task4()
    task4.xor_encrypt_image("./image/cp-logo.bmp", "./image/mustang.bmp")