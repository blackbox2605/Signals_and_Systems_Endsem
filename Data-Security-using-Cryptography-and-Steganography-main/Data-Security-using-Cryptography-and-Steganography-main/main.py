import os
import logging
import hashlib
from lib.Secure import Secure
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from zipfile import ZipFile
import getpass
import time

# Set up logging
logging.basicConfig(filename='secure_operations.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

secure = Secure()

# # AES Encryption/Decryption Utilities
# def aes_encrypt_file(input_file, output_file, key, key_size):
#     try:
#         cipher = AES.new(key, AES.MODE_EAX)
#         with open(input_file, 'rb') as f:
#             data = f.read()
#         ciphertext, tag = cipher.encrypt_and_digest(data)

#         with open(output_file, 'wb') as f_out:
#             [f_out.write(x) for x in (cipher.nonce, tag, ciphertext)]
#         logging.info(f"File {input_file} has been AES-encrypted with {key_size * 8}-bit key to {output_file}")
#         print(f"File {input_file} has been AES-encrypted to {output_file}")
#     except Exception as e:
#         logging.error(f"Error during AES encryption: {e}")
#         print(f"Error during encryption: {e}")

# def aes_decrypt_file(input_file, output_file, key):
#     try:
#         with open(input_file, 'rb') as f:
#             nonce, tag, ciphertext = [f.read(x) for x in (16, 16, -1)]
#         cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
#         data = cipher.decrypt_and_verify(ciphertext, tag)

#         with open(output_file, 'wb') as f_out:
#             f_out.write(data)
#         logging.info(f"File {input_file} has been AES-decrypted to {output_file}")
#         print(f"File {input_file} has been decrypted to {output_file}")
#     except Exception as e:
#         logging.error(f"Error during AES decryption: {e}")
#         print(f"Error during decryption: {e}")

# Compression and File Utilities
def compress_files(files, output_zip):
    try:
        with ZipFile(output_zip, 'w') as zip_file:
            for file in files:
                zip_file.write(file)
        logging.info(f"Files {files} compressed into {output_zip}")
        print(f"Files have been compressed into {output_zip}")
    except Exception as e:
        logging.error(f"Error compressing files: {e}")
        print(f"Error compressing files: {e}")

def decompress_file(zip_file, extract_dir):
    try:
        with ZipFile(zip_file, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
        logging.info(f"Compressed file {zip_file} decompressed to {extract_dir}")
        print(f"File {zip_file} has been decompressed to {extract_dir}")
    except Exception as e:
        logging.error(f"Error decompressing file: {e}")
        print(f"Error decompressing file: {e}")

# Hashing for Integrity Checks
def calculate_file_hash(file_path, hash_type='sha256'):
    try:
        hash_func = hashlib.new(hash_type)
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        logging.error(f"Error calculating hash for file {file_path}: {e}")
        print(f"Error calculating hash: {e}")
        return None

def check_file_integrity(original_file, decrypted_file):
    original_hash = calculate_file_hash(original_file)
    decrypted_hash = calculate_file_hash(decrypted_file)
    
    if original_hash == decrypted_hash:
        print("File integrity check passed. Files match.")
        logging.info(f"File integrity check passed for {original_file} and {decrypted_file}.")
    else:
        print("File integrity check failed. Files do not match.")
        logging.warning(f"File integrity check failed for {original_file} and {decrypted_file}.")

# Directory and File Utilities
def list_files_in_directory(directory):
    try:
        files = os.listdir(directory)
        if not files:
            print("No files found.")
        else:
            print(f"Files in {directory}:")
            for idx, file in enumerate(files):
                print(f"{idx+1}. {file}")
    except Exception as e:
        logging.error(f"Error listing files in directory: {e}")
        print(f"Error listing files: {e}")

# User Authentication for Access Control
def authenticate_user():
    try:
        password = getpass.getpass(prompt="Enter application password: ")
        if password == "securepassword":  # Replace with a hashed password check for production
            print("Access granted.")
            logging.info("User authenticated successfully.")
            return True
        else:
            print("Access denied. Incorrect password.")
            logging.warning("User authentication failed.")
            return False
    except Exception as e:
        logging.error(f"Error during authentication: {e}")
        print(f"Error during authentication: {e}")
        return False

# Progress Bar (for long tasks)
def progress_bar(duration):
    print("Processing...", end="", flush=True)
    for _ in range(duration):
        time.sleep(1)
        print(".", end="", flush=True)
    print(" Done!")

# Main Application
def main():
    if not authenticate_user():
        return

    while True:
        try:
            inp = int(input("""
1. Secure File into Image
2. Decrypt File from Image
3. Generate RSA Keys
4. Compress Files
5. Decompress File
6. Check File Integrity
7. List Available Cover Images
8. Exit
Choice: """))

            if inp == 1:
                fName = input('File to be secured: ')
                coverImg = input("Cover image location [default-lib/images/cover.img]: ")
                if coverImg != "" and os.path.isfile(coverImg):
                    logging.info(f"Securing file {fName} into image {coverImg}")
                    secure.secure_file(fName, coverImg)
                else:
                    print(f"Cover Image [{coverImg}] does not exist, using default...")
                    secure.secure_file(fName)
                print("File has been secured into image.")
            elif inp == 2:
                stegoImg = input("Stego image: ")
                fName = input('Output file name [default-lib/output/decrypted.txt]: ')
                if fName == "":
                    secure.desecure_file(stegoImg)
                else:
                    secure.desecure_file(stegoImg, fName)
                print(f"File decrypted from image {stegoImg}.")
            elif inp == 3:
                secure.generate_key()
                print("RSA Keys have been generated.")
            elif inp == 4:
                files = input('Enter file names to compress (comma separated): ').split(',')
                outZip = input('Output zip file name: ')
                compress_files(files, outZip)
            elif inp == 5:
                zipFile = input('Compressed zip file: ')
                extractDir = input('Directory to extract to: ')
                decompress_file(zipFile, extractDir)
            elif inp == 6:
                orig_file = input("Original file path: ")
                dec_file = input("Decrypted file path: ")
                check_file_integrity(orig_file, dec_file)
            elif inp == 7:
                list_files_in_directory('lib/images')
            elif inp == 8:
                print("Exiting...")
                break
            else:
                print("Invalid option. Try again.")
        except Exception as e:
            logging.error(f"Error in main menu: {e}")
            print(f"An error occurred: {e}")
            raise e

if __name__ == "__main__":
    main()