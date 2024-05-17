from typing import Union
from collections import defaultdict
import sys


class encryption:
    def __init__(self, plain_text: str, key: dict[str, Union[int, str]]):
        self.plain_text = plain_text.upper()
        self.key = {
            k: (
                "".join((list(v) * len(plain_text))[: len(plain_text)]).upper()
                if k == "vigerene"
                else (v.upper() if k == "mono" else v)
            )
            for k, v in key.items()
        }
        self.encrypted_text = {"caesar": "", "mono": "", "vigerene": ""}

    def log(self, file_name: str):
        """
        log a message to a file
        """
        with open(file_name, "w") as file:
            for cipher, encrypted in self.encrypted_text.items():
                file.write("[" + cipher + "]" + "\n")
                file.write("[PLAIN TEXT]: " + self.plain_text + "\n")
                file.write("[CIPHER TEXT]: " + encrypted + "\n\n\n")

    def encypt(self):
        """Encrypts message based off of encryption algorithm and key

        Returns:
            Encrypted_text: String in the encrypted text
        """
        for encryption in self.encrypted_text.keys():
            cipher_key = self.key[encryption]
            encrypted_text = ""
            if encryption == "Cesar Cipher":
                for char in self.plain_text:
                    shift = ord("A")  # assuming it's all uppercase
                    encrypted_text += chr((ord(char) - shift + cipher_key) % 26 + shift)

            if encryption == "Monoalphabetic Cipher":
                for char in self.plain_text:
                    shift_pos = ord(char) - ord("A")  # assuming it's all uppercase
                    encrypted_text += chr(
                        (ord(char) + ord(cipher_key[shift_pos])) % 26 + ord("A")
                    )

            if encryption == "Vigenere Cipher":
                for char_pos in range(len(self.plain_text)):
                    shift = self.key["Vigenere Cipher"][char_pos]
                    encrypted_text += chr(
                        (ord(self.plain_text[char_pos]) + ord(shift) + 1) % 26
                        + ord("A")
                    )

            self.encrypted_text[encryption] = encrypted_text


class Decryption:
    def __init__(self, encrypted_text: str, algo: str):
        self.encrypted_text = encrypted_text.upper()
        self.algo = algo
        self.decrypted_text = ""

    def output_decrypted_text(self):
        return self.decrypted_text

    def decrypt(self):
        parsed_encrypted_text = ""
        for letter in encrypted_text:
            if letter.isalpha():
                parsed_encrypted_text += letter.upper()

        if self.algo == "caesar":
            min_shift = self.chi_squared(parsed_encrypted_text)
            
            # decrypt the text with the best shift
            for char in self.encrypted_text:
                if char.isalpha():
                    self.decrypted_text += chr(
                        (ord(char) - ord('A') + min_shift) % 26 + ord("A")
                    )
                else:
                    self.decrypted_text += char

            print(min_shift )

        if self.algo == "mono":
            # decryption with frequency analysis on mono
            replacement_key = self.frequencyAnalysis(parsed_encrypted_text)
            for char in self.encrypted_text:
                if char.isalpha():
                    self.decrypted_text += replacement_key[char]
                else:
                    self.decrypted_text += char
            
        if self.algo == "vigerene":
            pass
        
    def frequencyAnalysis(self, parsed_encrypted_text: str):
        # frequency sorted by decending order of frequency (i.e. E is the most common letter in the english language)
        freq_chart = ["E", "T", "A", "O", "I", "N", "S", "R", "H", "D", "L", "U", "C", "M", "F", "Y", "W", "G", "P", "B", "V", "K", "X", "Q", "J", "Z"]
        print(parsed_encrypted_text)
        # count the occurence of each letter in the parsed encrypted text
        letter_count = defaultdict(int)
        for letter in parsed_encrypted_text:
            if letter.isalpha():
                if letter in letter_count:
                    letter_count[letter] += 1
                else:
                    letter_count[letter] = 1

        totoal_letters = sum(letter_count.values())
        letter_freq = {k: v / totoal_letters for k, v in letter_count.items()}
        
        # sort the letter frequency by decending order
        letter_freq = dict(sorted(letter_freq.items(), key=lambda item: item[1], reverse=True))
        
        replacement_key = {}
        for top_freq, letters_associate in zip(freq_chart, letter_freq.keys()):
            replacement_key[letters_associate] = top_freq
        print(letter_freq)
        print(replacement_key)

        print("".join(replacement_key.values()))
        print("".join(replacement_key.keys()))
        
        return replacement_key

    def chi_squared(self, parsed_encrypted_text: str):
        freq_analysis = {
                "A": 0.079, "B": 0.014, "C": 0.027, "D": 0.041, "E": 0.122,
                "F": 0.021, "G": 0.019, "H": 0.059, "I": 0.078, "J": 0.002,
                "K": 0.008, "L": 0.039, "M": 0.023, "N": 0.065, "O": 0.072,
                "P": 0.018, "Q": 0.001, "R": 0.058, "S": 0.061, "T": 0.088,
                "U": 0.027, "V": 0.010, "W": 0.023, "X": 0.002, "Y": 0.019,
                "Z": 0.010,
            }
        # use chi squared test to determine the best shift
        min_c2 = float("inf")
        min_shift = 0
        caesar_encrypt = parsed_encrypted_text
        for shift in range(26):
            c2 = 0
            # calculate chi squared over all letters on the parsed encrypted text
            for char in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                char_occurrence = caesar_encrypt.count(char)
                expected_occurrence = freq_analysis[char] * len(caesar_encrypt)
                c2 += (((char_occurrence - expected_occurrence) ** 2) / expected_occurrence)
            if c2 < min_c2:
                min_c2 = c2
                min_shift = shift
            # rotate all letters by 1
            caesar_encrypt = "".join(
                [
                    chr((ord(char) - ord('A') + 1) % 26 + ord("A"))
                    for char in caesar_encrypt
                ]
            )
        return min_shift

def process_encrypted_directory(directory: str):
    """
    Process a directory of encrypted text files, encrypted with caesar, mono, or vigerene ciphers
    """
    pass


if __name__ == "__main__":

    # keys = {
    #     "caesar": 3,
    #     "mono": "QWFPBXMJZKVYARNTCOSGHIDLEU",
    #     "vigerene": "CRYPTOGRAPHYCRYPTOGRAPHY",
    # }

    # assert len(keys["Monoalphabetic Cipher"]) == 26
    # assert len(keys["Vigenere Cipher"]) == len("THEREISNOSECURITYONTHISE")

    # encryption_instance = encryption("THEREISNOSECURITYONTHISE", key=keys)
    # encryption_instance.encypt()
    # encryption_instance.log("log.txt")
    import os

    # cesar cipher completed
    encrypted_file = "./mono_easy.txt"
    with open(encrypted_file, 'r') as file:
        file_name = os.path.basename(file.name).replace("encrypt", "decrypt")
        cipher_algo = file_name.split("_")[0]
        decrypted_file_path = os.path.join("./decrypted", file_name)
        encrypted_text = file.read()
        decryption_instance = Decryption(encrypted_text, cipher_algo)
        decryption_instance.decrypt()
        with open(decrypted_file_path, 'w') as decrypted_file:
            decrypted_file.write(decryption_instance.output_decrypted_text())


    # with open("/Users/zhihe/CPE321/encrypted 4/mono_easy_encrypt.txt", 'r') as file:
    #     encrypted_text = file.read()
    #     decryption_instance = Decryption(encrypted_text, "mono")
    #     decryption_instance.decrypt()
    #     print(decryption_instance.output_decrypted_text())