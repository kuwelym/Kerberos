import socket
import redis
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import rsa
import random
import string
from time import sleep

def load_public_key(filename):
    with open(filename, 'rb') as key_file:
        key_data = key_file.read()
        public_key = rsa.PublicKey.load_pkcs1(key_data)
    return public_key

def generate_random_key(length=16):
    return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(length)).encode()

def encrypt_aes(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(data, AES.block_size)
    return cipher.encrypt(padded_data)

def generate_ticket(username, session_key):
    return username + b",,," + session_key

def encrypt_rsa(data, public_key):
    return rsa.encrypt(data, public_key)

def create_encrypted_packet(session_key, encrypted_ticket):
    return session_key + b",,," + encrypted_ticket

def authenticate_client(client_socket, redis_db, public_key):
    username = client_socket.recv(1024)
    stored_password = redis_db.get(username.decode())
    
    if stored_password is None:
        print("Invalid credentials.")
        client_socket.close()
        return
    
    print("Client:", username.decode())
    print("Password received from DB.")
    
    secret_data = b'this is  testing'
    encrypted_secret = AES.new(stored_password, AES.MODE_ECB).encrypt(secret_data)
    
    session_key = generate_random_key()
    ticket = generate_ticket(username, session_key)
    encrypted_ticket = encrypt_rsa(ticket, public_key)
    
    packet = create_encrypted_packet(session_key, encrypted_ticket)
    encrypted_packet = encrypt_aes(packet, encrypted_secret)
    
    client_socket.send(encrypted_packet)
    sleep(1.0)
    print("Ticket sent to the client, connection closed.", username.decode())
    client_socket.close()

def main():
    redis_db = redis.Redis()
    redis_db.mset({b'khue': b'abcd1234abcd1234', b'bob': b'1234567890123456', b'alice': b'1234567890123456'})
    public_key_as_tgs = load_public_key('public_AS_TGS.pem')
    
    as_addr = socket.gethostname()
    as_port = 2000
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind((as_addr, as_port))
    serversocket.listen(5)
    print("Authentication server started.")
    
    while True:
        client_socket, addr = serversocket.accept()
        print("Client connected!")
        authenticate_client(client_socket, redis_db, public_key_as_tgs)

if __name__ == '__main__':
    main()
