import socket
from _thread import *
from cryptography.fernet import Fernet
import base64
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import datetime

mark = b'SIGNATURE'
server_public_key = None
client_public_key = None
server_private_key = None


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


def start_session(c):
    print('starting a new session with client...')
    data = c.recv(2048)
    session_cs = None
    expired_session = None
    remain = True
    if not data:
        print('received nothing from client!')
        remain = False
    try:
        data = decryption_rsa(server_private_key, data)
        valid_sign, data = signature_verification(data)
        if valid_sign:
            print('Signature is verified!')
            data = str(data.decode('ascii'))
        else:
            print('Signature is not verified!')
            data = 'invalid signature'.encode('ascii')
            data = encryption_rsa(client_public_key, data)
            remain = False
            c.send(data)
            return remain, None, None
    except InvalidToken:
        remain = False
        return remain, None, None
    except ValueError:
        remain = False
        return remain, None, None
    if data.startswith('session key:\n'):
        temp1 = data.find('\n') + 1
        temp2 = data[temp1:].find('\n') + temp1
        if temp2 == -1:
            remain = False
        else:
            pass_code = data[temp1:temp2]
            try:
                session_cs = session_key_generator(pass_code)
                expire_time = float(data[temp2 + 1:])
                expired_session = datetime.datetime.now() + datetime.timedelta(seconds=expire_time)
                data = 'accepted'.encode('ascii')
                data = sign_data(data)
                assert (len(data) <= 1024)
                data = encryption_rsa(client_public_key, data)
                c.send(data)
            except ValueError:
                remain = False
    else:
        remain = False
        print('Wrong RSA key!')
    return remain, session_cs, expired_session


def thread(c, addr):
    cont = bytes()
    connection_alive = True
    while connection_alive:
        remain, session_cs, expired_session = None, None, None
        for i in range(3):
            remain, session_cs, expired_session = start_session(c)
            if remain:
                connection_alive = True
                print('new session created!')
                break
            else:
                connection_alive = False
                print('session could not be created')
        while (expired_session - datetime.datetime.now()).days >= 0 and connection_alive:
            data = c.recv(2048)
            if not data:
                print('finished!')
                connection_alive = False
                break
            if not ((expired_session - datetime.datetime.now()).days >= 0):
                data = "key expired".encode('ascii')
                data = encryption(session_cs, data)
                c.send(data)
                break
            data = decryption(session_cs, data)
            valid_sign, data = signature_verification(data)
            if valid_sign:
                print('MAC verified')
            else:
                print('MAC not verified')
                break
            cont += data
            data = "send next".encode('ascii')
            data = sign_data(data)
            data = encryption(session_cs, data)
            c.send(data)
    c.close()
    out_file = open('.\\Received_from_' + addr[0] + '.jpg', 'wb')
    out_file.write(cont)


def Main():
    port = 8282
    host = ""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(5)
    print("listening for incoming requests...")
    while True:
        c, addr = s.accept()
        print('Connected to :', addr[0], ':', addr[1])
        start_new_thread(thread, (c, addr))


if __name__ == '__main__':
    print("please be patient it took a while to generate new keys...")
    private_key_server = rsa.generate_private_key(public_exponent=65537, key_size=8192, backend=default_backend())
    public_key_server = private_key_server.public_key()
    pem = private_key_server.private_bytes(encoding=serialization.Encoding.PEM,
                                           format=serialization.PrivateFormat.PKCS8,
                                           encryption_algorithm=serialization.NoEncryption())
    with open('.\\keys\\private_key_server.pem', 'wb') as f:
        f.write(pem)
    pem = public_key_server.public_bytes(encoding=serialization.Encoding.PEM,
                                         format=serialization.PublicFormat.SubjectPublicKeyInfo)
    with open('.\\keys\\public_key_server.pem', 'wb') as f:
        f.write(pem)
    private_key_client = rsa.generate_private_key(public_exponent=257, key_size=8192, backend=default_backend())
    public_key_client = private_key_client.public_key()
    pem = private_key_client.private_bytes(encoding=serialization.Encoding.PEM,
                                           format=serialization.PrivateFormat.PKCS8,
                                           encryption_algorithm=serialization.NoEncryption())
    with open('.\\keys\\private_key_client.pem', 'wb') as f:
        f.write(pem)
    pem = public_key_client.public_bytes(encoding=serialization.Encoding.PEM,
                                         format=serialization.PublicFormat.SubjectPublicKeyInfo)
    print("keys are generated!")
    with open('.\\keys\\public_key_client.pem', 'wb') as f:
        f.write(pem)
    with open(".\\keys\\private_key_server.pem", "rb") as key_table:
        server_private_key = serialization.load_pem_private_key(key_table.read(), password=None,
                                                                backend=default_backend())
    with open(".\\keys\\public_key_server.pem", "rb") as key_table:
        server_public_key = serialization.load_pem_public_key(key_table.read(), backend=default_backend())
    with open(".\\keys\\public_key_client.pem", "rb") as key_table:
        client_public_key = serialization.load_pem_public_key(key_table.read(), backend=default_backend())
    Main()
