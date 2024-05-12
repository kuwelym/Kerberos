# Kerberos Demo with Redis Database

This guide explains how to run the Kerberos demo written in Python, which utilizes Redis as the database. Kerberos is a network authentication protocol designed to provide strong authentication for client/server applications.

## Prerequisites

1. **Windows 10 with WSL2**: Ensure you are running Windows 10, version 1903 or higher, with the Windows Subsystem for Linux 2 (WSL2) enabled.
2. **WSL2 Installation**: Follow [Microsoft's documentation](https://docs.microsoft.com/en-us/windows/wsl/install) to install WSL2 on your Windows machine.
3. **WSL2 Distro**: You need a Linux distribution installed under WSL2. We recommend using Ubuntu or Debian for this guide.
4. **Python 3**: Ensure Python 3 is installed on your WSL2 distribution. You can install it using the package manager (`apt`) on Ubuntu or Debian.
5. **Redis Server**: Redis should be installed and running on your WSL2 distribution.
6. **Git Bash with OpenSSL**: Install Git Bash on your Windows machine and ensure that OpenSSL is available.

## Installing Redis on WSL2

Follow the instructions in the [Redis on Windows with WSL2](#running-redis-on-windows-with-wsl2) section of this README to install and set up Redis on your WSL2 distribution
Or
Follow the instructions from the official Redis website [Install Redis on Windows](https://redis.io/docs/latest/operate/oss_and_stack/install/install-redis/install-redis-on-windows/) to install.

### Ubuntu/Debian

1. Open the Microsoft Store.
2. Search for "Ubuntu" or "Debian" and install it.
3. Launch Ubuntu from the Start menu or by typing `ubuntu` or `debian` in the command prompt.
4. Update the package lists: `sudo apt update`.
5. Install Redis: `sudo apt install redis-server`.
6. Start the Redis service: `sudo service redis-server start`.

### Running Redis 

Once Redis is installed and running on your WSL2 distribution, you can access it from Windows or any application running on your Windows machine by connecting to `localhost` on the default Redis port (`6379`).

### Troubleshooting

If you encounter any issues during the installation or setup process, refer to the following resources:

- [WSL2 Installation Guide](https://docs.microsoft.com/en-us/windows/wsl/install)
- [Redis Quick Start](https://redis.io/topics/quickstart)

If Redis is not working or if you encounter errors, ensure that the Redis service is running in your WSL2 distribution. You can check the service status with the following command:

```bash
sudo service redis-server status
```

## Running the Kerberos

1. Clone this repository to your local machine:

   ```bash
   git clone https://github.com/kuwelym/Kerberos.git
   ```
2. Navigate to the directory of the cloned repository:
   ```bash
   cd Kerberos
   ```
3. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```
4. Open four separate terminal windows or tabs.
5. In the first terminal, navigate to the auth_server folder and run the authentication server:
   ```bash
   cd auth_server
   python auth_server.py
   ```
6. In the second terminal, navigate to the ticket_grant_server folder and run the ticket granting server:
   ```bash
   cd ticket_grant_server
   python ticket_grant_server.py
   ```
7. In the third terminal, navigate to the servers folder and run any servers you want to authenticate with Kerberos:
   ```bash
   cd servers
   python server.py
   ```
8. In the fourth terminal, navigate to the clients folder and run any clients you want to authenticate with Kerberos:
   ```bash
   cd clients
   python client.py
   ```

## Generating RSA Keys with OpenSSL

To generate RSA private and public keys using Git Bash with OpenSSL, follow these steps:

1. Open Git Bash on your Windows machine.

2. Run the following command to generate a private key (`private_tgs_server.pem`) using PKCS#1 format:

   ```bash
   openssl genrsa -traditional -out private_tgs_server.pem 4096
   ```
   * openssl genrsa: This command is used to generate an RSA private key.
   * -traditional: This flag specifies the use of the traditional SSLeay format for private keys (PKCS#1).
   * -out private_tgs_server.pem: Output file name where the generated private key will be saved.
   * 4096: Key length in bits.
3. Run the following command to generate the corresponding public key (public_tgs_server.pem) from the private key:
   ```bash
   openssl rsa -pubout -RSAPublicKey_out -in private_tgs_server.pem -out public_tgs_server.pem
   ```
   * openssl rsa: This command is used for various RSA key operations.
   * -pubout: Output should be a public key.
   * -RSAPublicKey_out: Output format for the public key.
   * -in private_tgs_server.pem: Input file name from which the public key will be generated.
   * -out public_tgs_server.pem: Output file name where the generated public key will be saved.
4. You now have both the private and public keys generated and ready for use in your Kerberos demo.

## Contributing
Contributions are welcome! If you find any errors or have suggestions for improvements, please open an issue or create a pull request.
