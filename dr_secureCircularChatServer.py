import socket
import threading
from datetime import datetime
import binascii
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

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

private_key = loadPrivateKey('./keys/eddytorres_private.pem')
public_key = loadPublicKey('./keys/eddytorres_public.pem')

def add_to_log(ip, message, direction):
    now = datetime.now()
    d_name = now.strftime("%d_%m_%Y")
    f = open('./sec_log/Server_' + ip + '_' + d_name + '.txt', 'a')
    now = datetime.now()
    current_time = now.strftime("%H:%M:%S")
    if(direction == 'S'):
        f.write(current_time + ' - Sent: ' + message + '\n')
    elif(direction == 'R'):
        f.write(current_time + ' - Received: ' + message + '\n')
    f.close()

def add_to_general_log(ip, port, message):
    now = datetime.now()
    d_name = now.strftime("%d_%m_%Y")
    f = open('./sec_log/Server_' + ip + '_' + port + '_' + d_name + '.txt', 'a')
    now = datetime.now()
    current_time = now.strftime("%H:%M:%S")
    f.write(current_time + ' - Received: ' + message + '\n')
    f.close()

def parse_message(message):
    message = message.strip('\0')
    message = message[4:]
    return message

def get_message(message):
    return str(len(message)+1).zfill(4)+message+'\n'

def deal_with_client(conn, addr):
    ip = str(addr[0])
    add_to_general_log(ip, str(addr[1]), 'Connected')

    try:
        while True:
            message = None
            while message is None:
                message = conn.recv(2048)

            add_to_general_log(ip, str(addr[1]), binascii.hexlify(message).decode('ASCII'))
            message = decrypt_message(private_key, message)
            message = parse_message(message)

            if(message != "DISCONNECT"):
                add_to_log(ip, message, 'R')
                message = get_message('OK')
                message = encrypt_message(public_key, message)
                conn.sendall(message)
                add_to_log(ip,  binascii.hexlify(message).decode('ASCII'), 'S')
            else:
                add_to_log(ip, message, 'R')
                message = get_message('DISCONNECT')
                message = encrypt_message(public_key, message)
                conn.sendall(message)
                add_to_log(ip,  binascii.hexlify(message).decode('ASCII'), 'S')
                break
        conn.close()
    except:
        message = get_message('DISCONNECT')
        message = encrypt_message(public_key, message)
        conn.sendall(message)
        add_to_log(ip,  binascii.hexlify(message).decode('ASCII'), 'S')
        conn.close()

if __name__ == "__main__":
    port_number = 9090
    bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsocket.bind(('127.0.0.1', port_number))
    bindsocket.listen(1)
    fromaddr = None

    print("Server listening at port: "+str(port_number))

    while True:
        try:
            newsocket, fromaddr = bindsocket.accept()
            t = threading.Thread(target=deal_with_client, args=(newsocket, fromaddr))
            t.start()
            print('Dealing with client: ' + str(fromaddr))
        except KeyboardInterrupt:
            print('Program closing...')
            break

    bindsocket.close()
