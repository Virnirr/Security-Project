from collections import defaultdict
import re

def frequency_analysis(text, n):
    if n == 0:
        freq_dict = {}
        for char in text:
            if char.isalpha():
                char = char.lower()
                freq_dict[char] = freq_dict.get(char, 0) + 1

        sorted_freq = sorted(freq_dict.items(), key=lambda x: x[1], reverse=True)
        return sorted_freq
    else:
        freq_dict = defaultdict(int)
        words = re.findall(r'\b\w+\b', text.lower())
        for word in words:
            if len(word) == n:
                freq_dict[word] += 1

        sorted_freq = sorted(freq_dict.items(), key=lambda x: x[1], reverse=True)
        return sorted_freq


def caesar(text, shift):
    result = []
    for char in text:
        if char.isalpha():
            shift_amount = 65 if char.isupper() else 97
            decrypted_char = chr((ord(char) - shift_amount - shift) % 26 + shift_amount)
            result.append(decrypted_char)
        else:
            result.append(char)
    return ''.join(result)


def main():
    file_path = 'vigenere_easy_encrypted.txt'
    try:
        # caesar cipher
        # with open(file_path, 'r') as file:
        #     ciphertext = file.read()
        #     print("Original Encrypted Text:")
        #     print(ciphertext)
        #     print("\nTrying all possible shifts:\n")
        #     #Try all possible shifts from 0 to 25
        #     for shift in range(1, 26):
        #         decrypted_text = caesar(ciphertext, shift)
        #         print(f"Shift {shift}: {decrypted_text}")

        # mono cipher
        with open(file_path, 'r') as f:
            ciphertext = f.read().strip()
        for n in range(0, 5):
            if n == 0:
                print("character frequency: ")
            else:
                print(str(n) + "-letter words:")
            result = frequency_analysis(ciphertext, n)
            for word, count in result:
                print(f"{word}: {count}")


        # # vigenere cipher
        with open(file_path, 'r') as file:
            # ciphertext = file.read()
            # vigenere(file_path)
            print("hello")

        
    except FileNotFoundError:
        print("File not found.")


if __name__ == "__main__":
    main()
