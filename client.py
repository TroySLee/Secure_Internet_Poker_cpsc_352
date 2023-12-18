# Gregory Martinez
# Troy Lee

import socket
import sys
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad

# Set up Key for AES (must be 16 keys)
#key = b'Sixteen byte key'
key = sys.argv[3].encode()

#AES encryption class
encCipher = AES.new(key, AES.MODE_ECB)
# Server's IP address
# SERVER_IP = "127.0.0.1"
SERVER_IP = sys.argv[1]

# The server's port number
# SERVER_PORT = 1235
SERVER_PORT = int(sys.argv[2])

# The client's socket
cliSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Attempt to connect to the server
cliSock.connect((SERVER_IP, SERVER_PORT))

# Send the message to the server
msg = input("Please enter a message to send to the server: ")



# Make plaintext into 16 bytes (padding)
#encode() function converts string into bytes
plainTextBytes = msg.encode()

paddedPlainTextBytes = pad(plainTextBytes, 16) #Pads text to be multiple of 16 bytes
print("Client padded text: ", paddedPlainTextBytes)

#AES encryption of paddedPlaintextBytes
cipherText = encCipher.encrypt(paddedPlainTextBytes)
print("Cipher text: ", cipherText)
open("encfile.bin", "wb").write(cipherText)

#Send message to server
cliSock.send(cipherText)


# Send the message to the server
# NOTE: the user input is of type string
# Sending data over the socket requires.
# First converting the string into bytes.
# encode() function achieves this.
#cliSock.send(msg.encode())

