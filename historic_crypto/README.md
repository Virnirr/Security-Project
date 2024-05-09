# Development

To contribute to this project:

Clone the repository

```console
cd historic_crypto
```

```console
python3 historicCrypto.py
```

Check out following lines of code to change file path:

```python
encrypted_file = "./encrypted 4/caesar_easy_encrypted.txt"
with open(encrypted_file, 'r') as file:
    file_name = os.path.basename(file.name).replace("encrypt", "decrypt")
    cipher_algo = file_name.split("_")[0]
    decrypted_file_path = os.path.join("./decrypted", file_name)
    encrypted_text = file.read()
    decryption_instance = Decryption(encrypted_text, cipher_algo)
    decryption_instance.decrypt()
    with open(decrypted_file_path, 'w') as decrypted_file:
        decrypted_file.write(decryption_instance.output_decrypted_text())
```