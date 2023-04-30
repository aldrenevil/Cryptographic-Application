# install streamlit: pip install streamlit
# run: streamlit run app.py

import streamlit as st
import random
from Crypto.Hash import keccak

def symmetric_encryption():
    def encrypt_caesar(plaintext, key):
        # Initialize an empty string for the ciphertext
        ciphertext = ""
        # Iterate through each character in the plaintext
        for char in plaintext:
            # Check if the character is a letter
            if char.isalpha():
                # Shift the ASCII value of the letter by the key value
                shifted = ord(char) + key
                # Check if the shifted value is outside the range of uppercase or lowercase letters
                if char.isupper():
                    if shifted > ord('Z'):
                        shifted -= 26
                    elif shifted < ord('A'):
                        shifted += 26
                else:
                    if shifted > ord('z'):
                        shifted -= 26
                    elif shifted < ord('a'):
                        shifted += 26
                # Add the shifted letter to the ciphertext
                ciphertext += chr(shifted)
            else:
                # Add non-letter characters to the ciphertext without modification
                ciphertext += char
        # Return the encrypted message
        return ciphertext

    def decrypt_caesar(ciphertext, key):
        # Call the encryption function with the negative key value
        return encrypt_caesar(ciphertext, -key)
    
    st.title("Caesar Cipher")
    st.write("## Discussion:")
    st.write("Caesar cipher is a simple substitution cipher in which each letter in the plaintext is shifted a certain number of positions down the alphabet. For example, if the shift is 3, then the letter A would be replaced by D, B would become E, and so on. The method is named after Julius Caesar, who is said to have used it to communicate with his officials.")
    st.write("## Application:")
    plaintext = st.text_input("Enter your message:", "Hello world!")
    shift = st.number_input("Enter the shift value:", min_value=1, max_value=25, value=3)

    col1, col2 = st.columns(2)

    if col1.button("Cipher"):
        encrypted_text = encrypt_caesar(plaintext, shift)
        st.write("Encrypted message:", encrypted_text)

    if col2.button("Decipher"):
        decrypted_text = decrypt_caesar(plaintext, shift)
        st.write("Decrypted message:", decrypted_text)


def asymmetric_encryption():

    st.title("Diffie-Hellman")

    st.write("## Discussion:")
    st.write("Diffie-Hellman key exchange is a method for two parties to securely share a secret key over an insecure communication channel. It is an example of asymmetric encryption, where each party has a public and private key. By exchanging public keys, the parties can generate a shared secret key that cannot be intercepted by eavesdroppers. The security of the key exchange relies on the difficulty of computing discrete logarithms.")
    st.write("## Application:")

    def generate_private_key(p):
        pri_key = random.randint(1, p - 1)
        return pri_key

    def generate_public_key(pri_key, p, g):
        pub_key = pow(g, pri_key, p)
        return pub_key

    def generate_shared_secret(private_key, public_key, p):
        shrd_key = pow(public_key, private_key, p)
        return shrd_key

    def encrypt_message(message, shared_secret):
        # XOR the message with the shared secret to encrypt the message
        encrypted_message = ''.join(chr(ord(c) ^ shared_secret) for c in message)
        return encrypted_message

    plaintext = st.text_input("Enter plaintext message:", "Hello World!")

    p = st.number_input("Enter a large prime number:", value=100043, step=1)
    g = st.number_input("Enter a primitive root of p:", value=100003, step=1)

    alice_private_key = generate_private_key(p)
    bob_private_key = generate_private_key(p)

    alice_public_key = generate_public_key(alice_private_key, p, g)
    bob_public_key = generate_public_key(bob_private_key, p, g)

    st.write("Alice's private key:", alice_private_key)
    st.write("Bob's private key:", bob_private_key)

    st.write("Alice's public key:", alice_public_key)
    st.write("Bob's public key:", bob_public_key)

    alice_shared_secret = generate_shared_secret(alice_private_key, bob_public_key, p)
    bob_shared_secret = generate_shared_secret(bob_private_key, alice_public_key, p)

    show_shared_secret = st.button("Show shared secret")
    if show_shared_secret:
        st.write("Shared secret: ", alice_shared_secret)

    # Alice encrypts a message
    alice_encrypted_message = encrypt_message(plaintext, alice_shared_secret)
    st.write("Alice's encrypted message:", alice_encrypted_message)

    # Bob encrypts a message
    bob_encrypted_message = encrypt_message(plaintext, bob_shared_secret)
    st.write("Bob's encrypted message:", bob_encrypted_message)
    
# Define function for hashing
def hashing():
    st.title("Keccak-512")
    st.write("## Discussion:")
    st.write("Keccak-512 is a cryptographic hash function that produces a 512-bit (64-byte) hash value. It is part of the Keccak family of hash functions and is designed to be secure against a wide range of attacks, including collision attacks, preimage attacks, and birthday attacks. It is commonly used in various applications such as digital signatures, data integrity verification, and password storage. Keccak-512 is considered to be a secure and efficient hash function, and is often used as an alternative to other widely-used hash functions like SHA-512.")
    st.write("## Application:")
    message = st.text_input("Enter message to hash:","Hello World!")
    if st.button("Hash"):
        keccak_hash = keccak.new(digest_bits=512, data=message.encode('utf-8')).hexdigest()
        st.write("Keccak-512 hash:", keccak_hash)
    

# Main Streamlit app
def main():
    st.title("Cryptographic Application")
    st.write("## Introduction:")
    st.write("Cryptography is an important tool for ensuring safe and accurate information on the Internet since there are several ways that may be used for security, such as symmetric encryption, encrypted Asymmetric Encryption, or hashing. Symmetrical encryption requires using the same key to encrypt and decode data. This strategy is speedier and more effective when dealing with big volumes of data. Asymmetric encryption encrypts data using a public key and decrypts it with a private key.  The approach offers stronger security but it is slower compared to the others due to its time-complexity. Hashing on the other hand generates a fixed-size output using a one-way function in which it may be used to validate the integrity of the data. In this cryptographic application Caesar Cipher for symmetric encryption, Diffie-hellman for asymmetric encryption, and Keccak-512 for hashing are implemented.")
    st.write("## Project Objectives:")
    st.write("1) Implement Caesar Cipher, Diffie-Hellman, and Keccak-512  in the system.\n2) Design a user-friendly interface for the system using Streamlit to allow users to easily encrypt, decrypt, and hash messages.\n 3) Demonstrate the use and implementation of these cryptographic techniques and highlighting their strengths and limitations.")
    # Create tabs
    tab1, tab2, tab3 = st.tabs(["Symmetric Cryptography", "Asymmetric Cryptography", "Hashing"])
    with tab1:
        symmetric_encryption()
    with tab2:
        asymmetric_encryption()
    with tab3:
        hashing()


    st.markdown(
        """
        <style>
        .footer {
            position: fixed;
            left: 0;
            bottom: 0;
            width: 100%;
            background-color: #f8f9fa;
            padding: 10px;
            text-align: center;
        }
        </style>
        """
    , unsafe_allow_html=True)

    # You can customize the footer content here
    st.markdown(
        """
        <div class="footer">
            Created by: Member1 Member2 Member3 - BSCS 3A/3B
        </div>
        """
    , unsafe_allow_html=True)

if __name__ == "__main__":
    main()