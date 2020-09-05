from hashlib import sha256
from pbkdf2_ctypes import *
import hmac
import hashlib
import binascii
from os import urandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import getpass
import sqlite3
from sqlite3 import Error
from pathlib import Path
from contextlib import closing

class PasswordRow:
    def __init__(self, service, password, salt, iv):
        self.service = service
        self.password = password
        self.salt = salt
        self.iv = iv


def getAesHash(password, keyHash, iv):
    """
    AES 256 encryption of the password for the service.
    the slice makes sure the key is the appropriate length
    for AES-256
    """
    backend = default_backend()
    key = keyHash[0:32]  # Make sure key is appropriate length
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(password.encode('utf-8')) + encryptor.finalize()
    return ct


def insertPwd(master, service, password):
    """
    Creates a password for a given service to be encrypted
    Encrypts the service with HMAC, and the password with AES-256
    Probably should be refactored, because this function does too much
    Inserts encrypted data (with salt and iv, so the keys can be re derived
    from the master password) into pwds table
    """
    master = master.encode('utf-8')
    service = service.encode('utf-8')
    # Create HMAC for the service
    hashSvc = hmac.new(master, service, hashlib.sha224)
    salt = urandom(32)
    # Key to be used for AES
    keyHash = pbkdf2_hex(masterpassword.encode('utf-8'), salt)
    iv = urandom(16)
    aesHash = getAesHash(password, keyHash, iv)  # Returns the actual encrypted password
    aesHash = binascii.hexlify(aesHash)
    aesHash = aesHash.decode()
    salt = binascii.hexlify(salt)
    salt = salt.decode()
    iv = binascii.hexlify(iv)
    iv = iv.decode()
    hashSvc = hashSvc.hexdigest()

    with closing(sqlite3.connect("passwords.db")) as connection:
        with closing(connection.cursor()) as cursor:
            cursor.execute("""INSERT into pwds (service, password, salt, iv) 
            values ('%s', '%s','%s','%s')""" %
                           (str(hashSvc), aesHash, salt, iv))
            connection.commit()

def getPwd(domain, masterpassword):
    """Retreives the password for a given domain name and
    the masterpassword
    """
    Passwords = {}
    with closing(sqlite3.connect("passwords.db")) as connection:
        with closing(connection.cursor()) as cursor:
            cursor.execute("SELECT * FROM pwds")
            for row in cursor:
                Passwords[row[0]] = row[1]  # Easy to use dict for service and passsword
                # newRow is a convenient class I created to store the data from a row from the password table
                # that holds all of the information needed to decrypt a password
                newRow = PasswordRow(row[0], row[1], row[2], row[3])
            domain = domain.encode('utf-8')
            masterpassword = masterpassword.encode('utf-8')
            hashSvc = hmac.new(masterpassword, domain, hashlib.sha224)
            hashSvc = hashSvc.hexdigest()
            if hashSvc in Passwords:  # Checks to see if user supplied domain exists
                decrypted = decryptPwd(newRow, masterpassword)  # If so, decrypt the password for the domain
                return decrypted
            else:
                return "Domain not found"
            connection.commit()



def decryptPwd(newRow, masterpassword):
    """Decrypts the password given the key, salt and iv
    from the row in the table that I used the class to conveniently store"""
    backend = default_backend()
    newRow.salt = newRow.salt.encode('utf-8')
    newRow.salt = binascii.unhexlify(newRow.salt)
    keyHash = pbkdf2_hex(masterpassword, newRow.salt)
    key = keyHash[0:32]  # Make sure key is appropriate length
    newRow.iv = newRow.iv.encode('utf-8')
    newRow.iv = binascii.unhexlify(newRow.iv)
    newRow.password = newRow.password.encode('utf-8')
    newRow.password = binascii.unhexlify(newRow.password)
    cipher = Cipher(algorithms.AES(key), modes.CFB(newRow.iv), backend=backend)
    decryptor = cipher.decryptor()
    newRow.password = decryptor.update(newRow.password) + decryptor.finalize()
    return newRow.password


def checkPwdTotal():
    """
    Simply checks how many passwords
    are stored in the master table.
    Its sorta an ugly hack for now
    :return:
    """
    with closing(sqlite3.connect("passwords.db")) as connection:
        with closing(connection.cursor()) as cursor:
            rows = cursor.execute("SELECT COUNT(*) FROM master").fetchall()
            if rows[0] ==1: #!= (0,):
                return 1
            else:
                return 0

def setMasterPwd(masterpassword):
    """
    stores the pbkdf2 hash of the master password, as well as the salt used
    so it can be later used to verify the user's entered master password
    """
    # The table should have only one master password stored
    # If there's already a master password, delete it
    tot = checkPwdTotal()
    if tot > 0:
        salt = urandom(16)
        masterpassword = pbkdf2_hex(masterpassword.encode('utf-8'), salt)
        password = masterpassword.decode()
        salt = binascii.hexlify(salt)
        salt = salt.decode()
        with closing(sqlite3.connect("passwords.db")) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute("""Delete from Master""")
                connection.commit()

        with closing(sqlite3.connect("passwords.db")) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute("""INSERT into master (pwd, salt) values ('%s', '%s')""" % \
                               (password, salt))
                connection.commit()

    else:
        salt = urandom(16)
        masterpassword = pbkdf2_hex(masterpassword.encode('utf-8'), salt)
        password = masterpassword.decode()
        salt = binascii.hexlify(salt)
        salt = salt.decode()
        with closing(sqlite3.connect("passwords.db")) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute("""INSERT into master (pwd, salt) values ('%s', '%s')""" % \
              (password, salt))
                connection.commit()

def checkMaster(masterpassword):
    """Checks to see if the master password entered
    by user is the same as the master password pbkdf2 hash stored in the
    database. Retrieves the hash and the salt, and calculates hash of the
    supplied master password"""
    with closing(sqlite3.connect("passwords.db")) as connection:
        with closing(connection.cursor()) as cursor:
            cursor.execute("SELECT * FROM master")
            for k, v in cursor:
                pwd = k
                salt = v
            salt = salt.encode('utf-8')
            salt = binascii.unhexlify(salt)
            newHash = pbkdf2_hex(masterpassword.encode('utf-8'), salt)
            newHash = newHash.decode()
            if pwd == newHash:
                return 1
            else:
                return 0
            connection.commit()




def checkIfDbExists(dbpath):
    """
    Checks if the local DB already exists when the program starts.
    If it does not exist create a new DB.
    """
    if dbpath.is_file():
        return
    else:
        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()

        # Create table
        c.execute('''CREATE TABLE master
                     (pwd text, salt text)''')

        c.execute('''CREATE TABLE pwds
                             (service text, password text, salt text, iv text)''')

        # Save (commit) the changes
        conn.commit()

        # We can also close the connection if we are done with it.
        # Just be sure any changes have been committed or they will be lost.
        conn.close()


if __name__ == "__main__":
    ans = True
    dbPath = Path("")
    checkIfDbExists(dbPath)
    while ans:
        print("==============================================================")
        print("* Welcome to the password manager, please enter your option  *")
        print("*                                                            *")
        print("*       1. Set master password                               *")
        print("*       2. Insert password for domain                        *")
        print("*       3. Retrieve password for domain                      *")
        print("*       4. Quit                                              *")
        print("*                                                            *")
        print("==============================================================")
        ans = input("What would you like to do? ")
        if ans == "1":
            masterpassword = getpass.getpass("Enter master password to set: ")
            setMasterPwd(masterpassword)
        elif ans == "2":
            masterpassword = getpass.getpass("Enter master password: ")
            domain = input('Enter domain: ')
            pwd = getpass.getpass("Enter password for domain: ")
            if pwd != 0:
                insertPwd(masterpassword, domain, pwd)
            else:
                print("Invalid master password")
        elif ans == "3":
            domain = input('Enter Domain to Get Password For: ')
            masterpassword = getpass.getpass("Enter master password: ")
            if checkMaster(masterpassword):
                resp = getPwd(domain, masterpassword)
                # print("You entered " + domain + " and it was found in the database")
                print("The password for " + domain + " is " + resp.decode())
                # else:
                #   print("Domain " + domain + " not found")
            else:
                print("Incorrect Master Password")
        elif ans == "4":
            print("Goodbye")
            ans = None
        else:
            print("Not Valid Choice Try again")
