import socket
import redis
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import rsa
import random
import string
from time import sleep
from datetime import datetime

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
    return username + b"||" + session_key

def encrypt_rsa(data, public_key):
    return rsa.encrypt(data, public_key)

def create_encrypted_packet(session_key, encrypted_ticket):
    return session_key + b"||" + encrypted_ticket

def authenticate_client(client_socket, redis_db, public_key, trusted_tgs_ids):
    username, tgs_id, timestamp = client_socket.recv(1024).split(b"||")
    print("Client:", username.decode())
    stored_password = redis_db.get(username.decode())
    
    if stored_password is None:
        print("Invalid credentials.")
        client_socket.close()
        return
    
    if tgs_id.decode() not in trusted_tgs_ids:
        print("Invalid TGS ID.")
        client_socket.close()
        return
    
    current_time = datetime.utcnow()
    request_time = datetime.strptime(timestamp.decode(), "%Y-%m-%d %H:%M:%S.%f")
    time_difference = (current_time - request_time).total_seconds()

    # Check if timestamp is within an acceptable window
    if abs(time_difference) > 1:
        print("Invalid timestamp.")
        client_socket.close()
        return
    print("Timestamp verified.")
    
    secret_data = b'this is  testing'

    # Encrypt secret_data(16 bytes) using AES in ECB mode with the stored password as the key.
    # Note: ECB mode is not recommended for most cryptographic purposes due to its vulnerabilities,
    # and using a password directly as a key is discouraged. Consider using a more secure mode
    # like CBC or GCM, and derive cryptographic keys from passwords using a key derivation function (KDF).
    encrypted_secret = AES.new(stored_password, AES.MODE_ECB).encrypt(secret_data)
    
    session_key = generate_random_key()
    TGT = generate_ticket(username, session_key)
    encrypted_TGT = encrypt_rsa(TGT, public_key)
    
    # The packet contains the session key and the encrypted TGT(ticket granting ticket)
    packet = create_encrypted_packet(session_key, encrypted_TGT)

    # The packet is encrypted with the secret key of the client
    encrypted_packet = encrypt_aes(packet, encrypted_secret)
    
    client_socket.send(encrypted_packet)
    sleep(1.0)
    print("Ticket sent to the client, connection closed.", username.decode())
    client_socket.close()

def main():
    redis_db = redis.Redis()
    redis_db.mset({b'khue': b'abcd1234abcd1234', b'bob': b'1234567890123456', b'alice': b'1234567890123456'})
    trusted_tgs_ids = ['TGS1', 'TGS2']
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
        authenticate_client(client_socket, redis_db, public_key_as_tgs, trusted_tgs_ids)

if __name__ == '__main__':
    main()
