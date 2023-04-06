#!/usr/bin/env python3
# (c)J~Net 2023
# jnet.sytes.net
#
# ./aes_aio.py
#
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


def generate_key(key_size):
    key=os.urandom(key_size//8)
    with open("key.txt", "wb") as f:
        f.write(key)


def encrypt_message():
    with open("key.txt", "rb") as f:
        key=f.read()

    with open("message.txt", "rb") as f:
        message=f.read()

    iv=os.urandom(16)
    with open("iv.txt", "wb") as f:
        f.write(iv)

    padder=padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data=padder.update(message) + padder.finalize()

    cipher=Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor=cipher.encryptor()
    ct=encryptor.update(padded_data) + encryptor.finalize()

    with open("encrypted.txt", "wb") as f:
        f.write(ct)


def decrypt_message():
    with open("key.txt", "rb") as f:
        key=f.read()

    with open("iv.txt", "rb") as f:
        iv=f.read()

    with open("encrypted.txt", "rb") as f:
        ct=f.read()

    cipher=Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor=cipher.decryptor()
    padded_data=decryptor.update(ct) + decryptor.finalize()

    unpadder=padding.PKCS7(algorithms.AES.block_size).unpadder()
    message=unpadder.update(padded_data) + unpadder.finalize()

    with open("decrypted.txt", "wb") as f:
        f.write(message)


def main():
    while True:
        print("Please select an option:")
        print("1. Generate AES key")
        print("2. Encrypt message")
        print("3. Decrypt message")
        print("4. Exit")
        choice=input("> ")

        if choice == "1":
            key_size=int(input("Enter key size in bits (128, 192, or 256): "))
            generate_key(key_size)
            print("Key Generated Successfully. Saved to key.txt")

        elif choice == "2":
            encrypt_message()
            print("Message Encrypted Successfully. Saved to encrypted.txt")

        elif choice == "3":
            decrypt_message()
            print("Message Decrypted Successfully.  Saved to decrypted.txt")

        elif choice == "4":
            print("Exiting program.")
            break

        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()

