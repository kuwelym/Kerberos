import socket
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import rsa
import random
import string
from time import sleep

def load_rsa_public_key(filename):
    with open(filename, mode='rb') as key_file:
        key_data = key_file.read()
        return rsa.PublicKey.load_pkcs1(key_data)

def load_rsa_private_key(filename):
    with open(filename, mode='rb') as key_file:
        key_data = key_file.read()
        return rsa.PrivateKey.load_pkcs1(key_data)

def generate_random_aes_key():
    return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(16)).encode()

def decrypt_rsa_message(ciphertext, private_key):
    return rsa.decrypt(ciphertext, private_key)

def encrypt_rsa_message(plaintext, public_key):
    return rsa.encrypt(plaintext, public_key)

def decrypt_aes_message(ciphertext, aes_key):
    cipher = AES.new(aes_key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext, 16)

def encrypt_aes_message(plaintext, aes_key):
    cipher = AES.new(aes_key, AES.MODE_ECB)
    padded_plaintext = pad(plaintext, 16)
    return cipher.encrypt(padded_plaintext)

def handle_client_request(client_socket, tgs_private_key, tgs_public_key):
    packet = client_socket.recv(1024).split(b",,,")

    if len(packet) != 3:
        print("Error: Invalid packet format")
        return

    requested_server_id, timestamp, encrypted_ticket1 = packet

    decrypted_ticket = decrypt_rsa_message(encrypted_ticket1, tgs_private_key).split(b",,,")

    if len(decrypted_ticket) != 2:
        print("Error: Invalid ticket format")
        return

    username, client_aes_key = decrypted_ticket

    print("Client", username.decode(), "requesting access to server-" + requested_server_id.decode())

    decrypted_timestamp = decrypt_aes_message(timestamp, client_aes_key)
    decrypted_timestamp = datetime.strptime(decrypted_timestamp.decode(), "%Y-%m-%d %H:%M:%S.%f")

    current_time = datetime.utcnow()

    if (current_time - decrypted_timestamp).seconds > 60:
        print("Error: Timestamp expired")
        return

    print("Timestamp verified.")

    server_session_key = generate_random_aes_key()

    server_ticket = requested_server_id + b",,," + server_session_key
    encrypted_server_ticket = encrypt_aes_message(server_ticket, client_aes_key)

    user_ticket = username + b",,," + server_session_key
    encrypted_user_ticket = encrypt_rsa_message(user_ticket, tgs_public_key)

    response_packet = encrypted_server_ticket + b",,," + encrypted_user_ticket

    sleep(1.0)
    client_socket.send(response_packet)
    print("Tickets sent to client,", username.decode(), ". Connection closed.")
    client_socket.close()

def main():
    tgs_public_key = load_rsa_public_key('public_TGS_SERVER.pem')
    tgs_private_key = load_rsa_private_key('private_AS_TGS.pem')

    tgs_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tgs_address = socket.gethostname()
    tgs_port = 3000
    tgs_socket.bind((tgs_address, tgs_port))
    print("Ticket granting server started.")

    while True:
        tgs_socket.listen(5)
        client_socket, addr = tgs_socket.accept()
        print("Client connected!")
        handle_client_request(client_socket, tgs_private_key, tgs_public_key)

if __name__ == '__main__':
    main()
