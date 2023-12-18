# Secure_Internet_Poker_cpsc_352
Group Members:
Troy Lee,
Gregory Martinez

video link:
https://www.youtube.com/watch?v=XTkZTyGrxlE

https://github.com/Barkinsons/Secure-Internet-Poker

(with the help of this referenced github we were able to record a demo video)

## Installation Requirements:

Install python3-pip and crypto library

sudo apt install python3-pipsudo pip3 install pycryptodomex

## How to run:

For this program, you will run server.py on one terminal and client.py in another terminal (respecfully) with the same port number and same key.

In server terminal:
python3 server.py < port number > < key >
EX: python3 server.py 1235 'sixteen byte key'

In client terminal:
python3 client.py < server ip > < server port > < key >
EX: python3 client.py 127.0.0.1 1235 'sixteen byte key'

When client connects to server successfully, client will be prompted to enter a message, encode it with AES and write it into encfile.bin
Server will receive AES encoded message, decode it with AES and write message in decfile.bin
