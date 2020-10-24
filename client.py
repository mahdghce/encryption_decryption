import socket
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from math import ceil
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import time
import random
import string
import datetime

mark = b'SIGNATURE'
server_public_key = None
client_public_key = None
client_private_key = None
session_cs = None
packet_length = 512


def decryption_rsa(private_key, cipher_text):
    plain_text = private_key.decrypt(cipher_text, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                               algorithm=hashes.SHA256(), label=None))
    return plain_text


def encryption_rsa(public_key, data):
    cipher_text = public_key.encrypt(data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                        algorithm=hashes.SHA256(), label=None))
    return cipher_text


def decryption(s_key, cipher_text):
    plain_text = s_key.decrypt(cipher_text)
    return plain_text


def encryption(s_key, data):
    cipher_text = s_key.encrypt(data)
    return cipher_text


def start_session(s):
    password_provided = ''.join(random.choice(string.ascii_lowercase) for i in range(10))
    expire_time = 20
    session_temp = None
    remain = False
    message = ("session key:\n" + password_provided + '\n' + str(expire_time)).encode('ascii')
    message = sign_data(message)
    assert (len(message) <= 1024)
    message = encryption_rsa(server_public_key, message)
    i = 0
    while i < 10:
        s.send(message)
        data = s.recv(2048)
        try:
            result = decryption_rsa(client_private_key, data)
            valid_signature, result = signature_verification(result)
            if valid_signature:
                print('signature is valid!')
                result = str(result.decode('ascii'))
            else:
                result = 'invalid signature'.encode('ascii')
                result = encryption_rsa(server_public_key, result)
                print('signature not valid!')
                remain = False
                s.send(result)
                return remain, None, None
            if result == "accepted":
                session_temp = session_key_generator(password_provided)
                expire_time = datetime.datetime.now() + datetime.timedelta(seconds=expire_time)
                remain = True
                break
        except InvalidToken:
            remain = False
        except ValueError:
            remain = False
    return remain, session_temp, expire_time


def sign_data(data):
    hash_algorithm = hashes.SHA256()
    hashing = hashes.Hash(hash_algorithm, default_backend())
    hashing.update(data)
    signature = hashing.finalize()
    return data + mark + signature


def signature_verification(signed_data):
    message = None
    valid_data = True
    try:
        split_data = signed_data.split(mark)
        assert (len(split_data) == 2)
        data = split_data[0]
        signature = split_data[1]
        hash_algorithm = hashes.SHA256()
        hashing = hashes.Hash(hash_algorithm, default_backend())
        hashing.update(data)
        new_signature = hashing.finalize()
        assert (new_signature == signature)
        message = data
    except AssertionError:
        valid_data = False
    return valid_data, message


def session_key_generator(pass_code):
    password = pass_code.encode()
    salt = b'salt_MGHBOY'  # can be changed
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    session_key = Fernet(base64.urlsafe_b64encode(kdf.derive(password)))
    return session_key


def Main():
    host = '127.0.0.1'
    port = 8282
    client_answer = input('\naddress of a file to send or type "exit":\n')
    if client_answer == 'exit':
        return
    else:
        f = open(client_answer, "rb")
        content = f.read()
        f.close()
        number_of_packets = ceil(len(content) / float(packet_length))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    packet_counter = 0
    while packet_counter < number_of_packets:
        global session_cs  # here
        remain, session_cs, session_expire = start_session(s)
        if not remain:
            print('session did not start!')
            break
        while ((session_expire - datetime.datetime.now()).days >= 0) and packet_counter < number_of_packets:
            start = packet_counter * packet_length
            end = start + packet_length
            message = content[start:end]
            message = sign_data(message)
            message = encryption(session_cs, message)
            s.send(message)
            data = s.recv(2048)
            try:
                data = decryption(session_cs, data)
                valid_sign, data = signature_verification(data)
                if valid_sign:
                    data = str(data.decode('ascii'))
                    print('MAC is correct')
                else:
                    print('WARNING! MAC is not correct')
                    break
            except InvalidToken:
                print('error in decrypting data, expected session_cs')
                break
            if data == "send next":
                packet_counter += 1
            elif data.startswith('key expired'):
                break
            else:
                break
            time.sleep(1)
    s.close()


if __name__ == '__main__':
    with open(".\\keys\\private_key_client.pem", "rb") as key_table:
        client_private_key = serialization.load_pem_private_key(key_table.read(), password=None,
                                                                backend=default_backend())
    with open(".\\keys\\public_key_server.pem", "rb") as key_table:
        server_public_key = serialization.load_pem_public_key(key_table.read(), backend=default_backend())
    with open(".\\keys\\public_key_client.pem", "rb") as key_table:
        client_public_key = serialization.load_pem_public_key(key_table.read(), backend=default_backend())
    Main()
