import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import cryptography
from cryptography.fernet import Fernet
import sys
from os import system, name


def clear():
    # for windows
    if name == 'nt':
        _ = system('cls')

        # for mac and linux(here, os.name is 'posix')
    else:
        _ = system('clear')


def key_generate(input_password):
    global f
    encoded_password = input_password.encode()  # Convert to type bytes
    salt = b'A\xa2*\xa7\x8c^\xa0)p\xa1\xe4\xb8\xf7e\xa3\xbd'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(encoded_password))
    f = Fernet(key)


def validate_password(pass_word):
    if len(pass_word) < 6:
        print("\nPassword should be longer than 5 characters")
    elif len(pass_word) > 30:
        print("\nPassword should not be longer than 30 characters")
    else:
        if pass_word.isdigit():
            print("Password should be a mix of alpha numeric characters\n")
        else:
            return 1


def encrypt_file(file_name):
    with open(file_name, 'r') as file_r:
        insecure_content = file_r.read()
    secure_content = encrypt(insecure_content)
    with open(file_name, "wb") as file_w:
        file_w.write(secure_content)
    return 1


def decrypt_file(file_name):
    with open(file_name, 'rb') as file_r:
        secure_content = file_r.read()
    insecure_content = decrypt(secure_content)
    if insecure_content != -1:
        with open(file_name, "w") as file_w:
            file_w.write(insecure_content)
    else:
        return -1
    return 1


def encrypt(message):
    global f
    encoded_message = message.encode()
    encrypted = f.encrypt(encoded_message)
    return encrypted


def decrypt(message):
    global f
    try:
        decrypted = f.decrypt(message)
    except cryptography.fernet.InvalidToken:
        return -1
    output = decrypted.decode()
    return output


def multiple():
    single = False
    inp2 = input("Do you want to encrypt or decrypt multiple files (e/d)>>").strip().lower()
    if (inp2 == "back") or (inp2 == "exit"):
        return
    if inp2 == "e":
        inp3 = input("Enter two or more file names separated by a space to encrypt>>").strip()
        file_names = inp3.split()
        if len(file_names) == 1:
            print("You can directly use 'e' to encrypt a single file")
            single = True
        for i in range(len(file_names)):
            if not file_names[i].endswith(".txt"):
                file_names[i] += ".txt"
            try:
                dummy = open(file_names[i], "r")
                dummy.close()
            except FileNotFoundError:
                print(f"Could not find {file_names[i]}")
                print("Check if you misspelled the file name and if the file is in the same directory as this program")
                break
        else:
            if single:
                print(f"\nEnter a password to securely encrypt the {file_names[0]}")
            else:
                print("\nEnter a password to securely encrypt the files")
            print("You will require the same password while decrypting, make sure you remember it")
            print("You cannot retrieve your data if you forget the password")
            password = input("\nEnter a password>>")
            while validate_password(password) != 1:
                password = input("Enter a valid password>>")
            else:
                key_generate(password)
            for i in range(len(file_names)):
                if encrypt_file(file_names[i]) != 1:
                    print(f"Something went wrong while encrypting {file_names[i]}, try again")
                    break
            else:
                clear()
                print("Encryption was successful")

    elif inp2 == "d":
        inp3 = input("Enter two or more file names separated by a space to decrypt>>").strip()
        file_names = inp3.split()
        if len(file_names) == 1:
            print("You can directly use 'd' to decrypt a single file")
            single = True
        for i in range(len(file_names)):
            if not file_names[i].endswith(".txt"):
                file_names[i] += ".txt"
            try:
                dummy = open(file_names[i], "r")
                dummy.close()
            except FileNotFoundError:
                print(f"\nCould not find {file_names[i]}")
                print("Check if you misspelled the file name and if the file is in the same directory as this program")
                break
        else:
            if single:
                password = input(f"\nEnter the password which was used to encrypt {file_names[0]}>>").strip()
            else:
                password = input(f"\nEnter the password which was used to encrypt the files>>").strip()
            key_generate(password)
            for i in range(len(file_names)):
                decryption = decrypt_file(file_names[i])
                if decryption == -1:
                    clear()
                    print("\nOne or more files could not be decrypted")
                    print("Most probably the password that you entered might be incorrect")
                    print("You must enter the same password which was used to encrypt all the files")
                    password = input("\nYou can try 'help' for more info or just press 'Enter' to return to the main screen>>").strip().lower()
                    if password == "help":
                        print("\nThe below given information is only applicable if you are sure that you entered the right password, but could not decrypt your files...")
                        print("\nOne or more files might already be decrypted, if not it might be that some of the encrypted files were tampered")
                        print("Your data is not recoverable if it was the latter case")
                        input("\nPress 'Enter' to return to main screen>>")
                        break
                    else:
                        break
                elif decryption == 1:
                    encrypt_file(file_names[i])
            else:
                for i in range(len(file_names)):
                    decrypt_file(file_names[i])
                clear()
                print(f"\nDecryption was successful")
                print("If you did not retrieve your data, it might be due to multilayer encryption")
                print("You can try decrypting a file repeatedly till you retrieve your data")
                return
    else:
        print("Expected 'e' for encryption or 'd' for decryption")


def main():
    print("Hi there! Welcome to this python cryptography program")
    print("Encrypt and decrypt text files with a single command, try now...")
    print("Use 'e' to encrypt and 'd' to decrypt, followed by a file name. Use 'q' to quit the program")
    print("For example enter 'e air' to encrypt the text file named air, entering '.txt' after file name is not required")
    print("Use 'm' to encrypt or decrypt multiple files at once")
    while True:
        inp = input("\n'e', 'd' or 'm', use 'q' to exit>>")
        split_input = inp.strip().lower().split()
        if inp.lower().strip() == "q":
            sys.exit()
        elif (inp.lower().strip() == "e") or (inp.lower().strip() == "d"):
            print("A file name was expected")
        elif inp.lower().strip() == "m":
            multiple()
        elif len(split_input) == 2:
            file_tag = split_input[1]
            if not file_tag.endswith(".txt"):
                file_tag = file_tag + ".txt"
            if split_input[0] == "e":
                try:
                    file_r = open(file_tag, "r")
                    file_r.close()
                except FileNotFoundError:
                    print(f"Could not find {file_tag}, check if you misspelled the file name and if the file is in the same directory as this program")
                    continue
                print(f"\nEnter a password to securely encrypt {file_tag}")
                print("You will require the same password while decrypting, make sure you remember it")
                print("You cannot retrieve your data if you forget the password")
                password = input("\nEnter a password>>")
                while validate_password(password) != 1:
                    password = input("Enter a valid password>>")
                else:
                    key_generate(password)
                if encrypt_file(file_tag) == 1:
                    clear()
                    print(f"\nSuccessfully encrypted {file_tag}")
            elif split_input[0] == "d":
                try:
                    file_r = open(file_tag, "r")
                    file_r.close()
                except FileNotFoundError:
                    print(f"Could not find {file_tag}, check if you misspelled the file name and if the file is in the same directory as this program")
                    continue
                password = input(f"Enter the password which was used to encrypt {file_tag}>>")
                key_generate(password)
                while True:
                    decryption = decrypt_file(file_tag)
                    if decryption == -1:
                        print("Incorrect password, try again")
                        password = input("\nEnter password again, you can enter 'help' for advanced help>>").strip()
                        if password.lower() == "help":
                            print("\nThe below given information is only applicable if you are sure that you entered the right password, but could not decrypt your file...")
                            print("\nThe file might already be decrypted, if not it might be that the encrypted file was tampered")
                            print("Your data is not recoverable if it was the latter case")
                            input("\nPress 'Enter' to quit advanced options>>")
                            break
                        else:
                            key_generate(password)
                    elif decryption == 1:
                        clear()
                        print(f"\nSuccessfully decrypted {file_tag}")
                        print("If you did not retrieve your data, it might be due to multilayer encryption")
                        print("You can try decrypting repeatedly till you retrieve your data")
                        break
            else:
                print("That was not expected, try again...")
        else:
            print("That was not expected, try again...")


if __name__ == "__main__":
    main()
