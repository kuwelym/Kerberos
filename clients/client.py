import socket
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def take_input():
    username = input("Enter your username: ")
    password = input("Enter your password(16-digits): ").encode()
    tgs_id = input("Enter TGS ID: ")
    secret_data = b'this is  testing'
    session_key = generate_session_key(password, secret_data)
    return username, session_key, tgs_id

def generate_session_key(password, data):
    cipher = AES.new(password, AES.MODE_ECB)
    return cipher.encrypt(data)

def connect_to_authentication_server(username, tgs_id):
    authentication_server_address = socket.gethostname()
    authentication_server_port = 2000
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((authentication_server_address, authentication_server_port))

    # Send username, TGS ID, and timestamp to authentication server
    timestamp = str(datetime.utcnow())
    request_data = f"{username}||{tgs_id}||{timestamp}".encode()

    client_socket.send(request_data)
    response  = client_socket.recv(1024)
    client_socket.close()
    return response 

def decrypt_packet(packet, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_packet = cipher.decrypt(packet)
    return unpad(decrypted_packet, AES.block_size)

def connect_to_ticket_granting_server(packet, key1):
    decrypted_packet = decrypt_packet(packet, key1)
    if decrypted_packet == b"":
        print("Invalid credentials!")
        exit(0)
    print("Authenticated by authentication server.")
    decrypted_packet_parts = decrypted_packet.split(b"||")
    if len(decrypted_packet_parts) != 2:
        print("Invalid credentials!")
        exit(0)
    session_key, ticket_to_tgs = decrypted_packet_parts
    timestamp = str(datetime.utcnow()).encode()
    timestamp_encrypted = encrypt_with_key(session_key, timestamp)
    server_id = input("Enter serverID: ").encode()
    packet  = server_id + b"||" + timestamp_encrypted + b"||" + ticket_to_tgs
    ticket_granting_server_address = socket.gethostname()
    ticket_granting_server_port = 3000
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((ticket_granting_server_address, ticket_granting_server_port))
    return send_and_receive(packet , client_socket), session_key

def send_and_receive(data, client_socket):
    client_socket.send(data)
    response = client_socket.recv(1024)
    return response

def encrypt_with_key(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(data, AES.block_size)
    return cipher.encrypt(padded_data)

def connect_to_server(packet, session_key):
    packet_parts = packet.split(b"||")
    if len(packet_parts) != 2:
        print("Invalid credentials!")
        exit(0)
    ticket_to_server, ticket_to_client = packet_parts
    ticket_to_server_decrypted = decrypt_packet(ticket_to_server, session_key)
    _, server_key = ticket_to_server_decrypted.split(b"||")
    timestamp_request = str(datetime.utcnow()).encode()
    timestamp_request_encrypted = encrypt_with_key(server_key, timestamp_request)
    packet = timestamp_request_encrypted + b"||" + ticket_to_client
    server_address = socket.gethostname()
    server_port = 4000
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_address, server_port))
    timestamp_encrypted_response = send_and_receive(packet, client_socket)
    timestamp_response = decrypt_packet(timestamp_encrypted_response, server_key)
    timestamp_response_formatted = datetime.strptime(timestamp_response.decode(), "%Y-%m-%d %H:%M:%S.%f")
    timestamp_request_formatted = datetime.strptime(timestamp_request.decode(), "%Y-%m-%d %H:%M:%S.%f")
    if (timestamp_request_formatted - timestamp_response_formatted).seconds == 1:
        print("Connection established with server.")
        return "True", client_socket, server_key
    else:
        return "False", None, None

def communicate_with_server(client_socket, server_key):
    print("Server connected!")
    while True:
        text = input("Enter string: ").encode()
        encrypted_text = encrypt_with_key(server_key, text)
        client_socket.send(encrypted_text)
        if text.decode() == "quit":
            print("Disconnected from server.")
            break

        encrypted_reply = client_socket.recv(1024)
        reply = decrypt_packet(encrypted_reply, server_key)
        print("Received message:", reply.decode())
    client_socket.close()

def main():
    username, key1, tgs_id = take_input()
    AS_response = connect_to_authentication_server(username, tgs_id)
    TGS_response, session_key = connect_to_ticket_granting_server(AS_response, key1)
    reply, client_socket, server_key = connect_to_server(TGS_response, session_key)
    if reply == "True":
        communicate_with_server(client_socket, server_key)
    else:
        print("Error in communication, try again later.")

if __name__ == '__main__':
    main()
