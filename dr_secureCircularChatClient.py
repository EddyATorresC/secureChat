import socket
import random
from datetime import datetime
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

def loadPrivateKey(path):
    private_key = RSA.import_key(open(path).read())
    return private_key

def loadPublicKey(path):
    receiver_key = RSA.import_key(open(path).read())
    return receiver_key

def encrypt_message(public_key, unencrypted_message):
    encryptor = PKCS1_OAEP.new(public_key)
    encrypted = encryptor.encrypt(unencrypted_message.encode('ASCII'))
    return encrypted

def decrypt_message(private_key, encrypted_message):
    decryptor = PKCS1_OAEP.new(private_key)
    decrypted = decryptor.decrypt(encrypted_message)
    return decrypted.decode('ASCII')

private_key = loadPrivateKey('./keys/eddytorres_public.pem')
public_key = loadPublicKey('./keys/Mike_Pinta_public.pem')

def send(message, s):
    if s is not None:
        # message = '200.21.44.1|205950'
        message = encrypt_message(public_key, message)
        s.sendall(message)
        write_to_log(binascii.hexlify(message).decode('ASCII'), 'S')
        data = None
        while data is None:
            data = s.recv(2048)
        data = decrypt_message(private_key, data)
        write_to_log(data, 'R')

def write_to_log(message, direction):
    f = open('./sec_log/Client_CircularTest.txt', 'a')
    now = datetime.now()
    current_time = now.strftime("%H:%M:%S")
    if direction == 'S':
        f.write(current_time + ' - Sent: ' + message + '\n')
    elif direction == 'R':
        f.write(current_time + ' - Received: ' + message + '\n')
    f.close()

if __name__ == '__main__':

    ServerIP = 'husky.spellkaze.com'
    ServerPort = 9090

    #ServerIP = '104.197.125.87'
    #ServerPort = 9090
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ServerIP, ServerPort))

    send('message', s)
    send('0011DISCONNECT\0', s)
    s.close()
