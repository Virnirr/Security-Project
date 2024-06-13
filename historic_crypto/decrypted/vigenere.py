import string

def main():
    ciphertext = open("vigenere_hard_encrypt.txt", "r")
    line = ciphertext.read()
    my_len = 13
    key = find_key(my_len, line)

    # get key in ascii
    answer_key = get_key_ascii(key)
    print("Key: ", answer_key, '\n')
    print(vigenere(line, answer_key))

def get_key_ascii(arr):
    alphabet = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j",
    "k", "l", "m", "n", "o", "p", "q", "r", "s", "t",
    "u", "v", "w", "x", "y", "z"]
    key = ""
    for i in arr:
        key += alphabet[i]
    return key

def find_key(key_len, line):
    line = line.replace('“', '')
    line = line.replace('”', '')
    line = line.replace('’', '')
    line = line.replace('—', '')
    line = line.translate(str.maketrans('', '', string.punctuation))
    line = ''.join(line.split())
    key = [0] * key_len
    lines_array = [''] * key_len
    for i in range(len(line)):
        lines_array[i % key_len] += line[i]

    index = 0
    for x in lines_array:
        key[index] = frequency_calculation(x)
        index += 1
    return key

def frequency_calculation(line):
    expected_freqs = [ 8.2, 1.5, 2.8, 4.3, 12.7, 2.2, 2.0, 6.1, 7.0, 0.2, 0.8, 
    4.0, 2.4, 6.7, 7.5, 1.9, 0.1, 6.0, 6.3, 9.1, 2.8, 1.0, 2.4, 0.2, 2.0, 0.1]

    alphabet = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j",
    "k", "l", "m", "n", "o", "p", "q", "r", "s", "t",
    "u", "v", "w", "x", "y", "z"]

    letter_occurences = [0] * 26
    # count letter frequencies
    for letter in line:
        if letter.isalpha():
            letter_occurences[alphabet.index(letter.lower())] += 1
            shifts = [0] * 26
    for i in range(26):
        tmp = []
        for j in range(26):
            j_idx = index_in_list2 = (j - i) % 26
            tmp.append(letter_occurences[j] * expected_freqs[j_idx])
        shifts[i] = tmp

    possible_keys = [0] * 26
    n = 0

    for row in shifts:
        m = 0
        total = 0
        while m < 26:
            total += row[m]
            m += 1
        possible_keys[n] = total
        n += 1
    winner = possible_keys.index(max(possible_keys))
    return winner

def vigenere(ciphertext_line, key):
    alphabet = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j",
    "k", "l", "m", "n", "o", "p", "q", "r", "s", "t",
    "u", "v", "w", "x", "y", "z"]
    new_line = ""
    i = 0
    for letter in ciphertext_line:
        if letter.isalpha():
            key_char = key[i % len(key)]
            key_index = alphabet.index(key_char)

            decrypted_char = alphabet[(alphabet.index(letter) - key_index) % 26]
            new_line += decrypted_char
            i += 1
        else:
            new_line += letter
    return new_line


if __name__ == "__main__":
    main()
