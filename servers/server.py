import socket
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import rsa
from time import sleep

def load_private_key(filename):
    with open(filename, mode='rb') as private_key_file:
        key_data = private_key_file.read()
        return rsa.PrivateKey.load_pkcs1(key_data)

def decrypt_ticket(ticket, private_key):
    return rsa.decrypt(ticket, private_key)

def verify_ticket(client_socket, private_key_file):
    try:
        tgs_private_key = load_private_key(private_key_file)

        packet = client_socket.recv(1024).split(b"||")

        if len(packet) != 2:
            raise ValueError("Invalid packet format")

        timestamp, encrypted_ticket = packet

        ticket_data = decrypt_ticket(encrypted_ticket, tgs_private_key).split(b"||")

        if len(ticket_data) != 2:
            raise ValueError("Invalid ticket format")

        username, session_key = ticket_data

        cipher = AES.new(session_key, AES.MODE_ECB)
        decrypted_timestamp = unpad(cipher.decrypt(timestamp), 16)
        decrypted_timestamp = datetime.strptime(decrypted_timestamp.decode(), "%Y-%m-%d %H:%M:%S.%f")

        current_time = datetime.utcnow()

        if (current_time - decrypted_timestamp).seconds > 120:
            return False, b"", b""

        previous_timestamp = decrypted_timestamp - timedelta(seconds=1)
        previous_timestamp_bytes = str(previous_timestamp).encode()
        previous_timestamp_padded = pad(previous_timestamp_bytes, 16)
        previous_timestamp_encrypted = cipher.encrypt(previous_timestamp_padded)

        client_socket.send(previous_timestamp_encrypted)
        print("Ticket verified.")
        return True, username, session_key

    except Exception as e:
        print("Error during ticket verification:", e)
        return False, b"", b""

def serve_client(client_socket, username, session_key):
    start_time = datetime.utcnow()
    print("Serving client " + username.decode() + ".")

    while True:
        current_time = datetime.utcnow()

        if (current_time - start_time).seconds > 60:
            client_socket.close()
            print("Session timed out.")
            break

        encrypted_message = client_socket.recv(1024)
        cipher = AES.new(session_key, AES.MODE_ECB)
        decrypted_message = unpad(cipher.decrypt(encrypted_message), 16)
        text = decrypted_message.decode()

        print("Received message:", text)

        if text == "quit":
            print("Client", username.decode(), "disconnected.")
            return

        response = input("Enter response: ").encode()
        sleep(1.0)
        padded_response = pad(response, 16)
        encrypted_response = cipher.encrypt(padded_response)
        client_socket.send(encrypted_response)

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = socket.gethostname()
    server_port = 4000
    server_socket.bind((server_address, server_port))
    server_socket.listen(5)
    print("Server started.")

    while True:
        client_socket, address = server_socket.accept()
        print("Incoming client...")

        success, username, session_key = verify_ticket(client_socket, 'private_TGS_SERVER.pem')

        if success:
            serve_client(client_socket, username, session_key)
        else:
            client_socket.close()

if __name__ == '__main__':
    main()
