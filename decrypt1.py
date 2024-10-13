import base64
from Crypto.Cipher import DES3
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad

def decrypt(passphrase, ciphertext):
    try:
        # Decode the base64 ciphertext
        encrypted_data = base64.b64decode(ciphertext)
        
        # Extract salt, IV, and encrypted content
        salt = encrypted_data[:24]
        iv = encrypted_data[24:32]
        encrypted_content = encrypted_data[32:]
        
        # Generate key using PBKDF2
        key = PBKDF2(passphrase.encode(), salt, dkLen=24, count=1000)
        
        # Create cipher object
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        
        # Decrypt and unpad
        decrypted = unpad(cipher.decrypt(encrypted_content), DES3.block_size)
        
        return decrypted
    except Exception as e:
        print(f"Error in decryption: {str(e)}")
        return None

def main():
    print("-----------------------------------------------------")
    print("SolarPutty's Sessions Decrypter (Python Version)")
    print("-----------------------------------------------------")
    
    file_path = input("Enter the path to the session file: ")
    password = input("Enter the password (press Enter if none): ")
    
    try:
        with open(file_path, 'rb') as file:
            ciphertext = file.read()
        
        print(f"File content (first 50 bytes): {ciphertext[:50]}")
        
        decrypted_data = decrypt(password, ciphertext)
        
        if decrypted_data:
            try:
                decrypted_text = decrypted_data.decode('utf-8')
                print("\nDecrypted content:")
                print(decrypted_text)
                
                output_file = "SolarPutty_sessions_decrypted.txt"
                with open(output_file, 'w') as file:
                    file.write(decrypted_text)
                
                print(f"\n[+] DONE Decrypted file is saved in: {output_file}")
            except UnicodeDecodeError:
                print("\nDecrypted content (binary, first 100 bytes):")
                print(decrypted_data[:100])
                
                output_file = "SolarPutty_sessions_decrypted.bin"
                with open(output_file, 'wb') as file:
                    file.write(decrypted_data)
                
                print(f"\n[+] DONE Decrypted binary file is saved in: {output_file}")
        else:
            print("Decryption failed.")
    
    except FileNotFoundError:
        print(f"Error: File not found - {file_path}")
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")

if __name__ == "__main__":
    main()
