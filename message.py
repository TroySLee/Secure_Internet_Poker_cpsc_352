#Send and get functions according to a specific format     

import struct

from mydigitalsignature import DigitalSignature as DS
from Cryptodome.Hash import SHA1
from Cryptodome.Cipher import AES

# Used for type hinting
import socket
from Cryptodome.PublicKey import RSA, DSA

class Message:
    
    def get(connection: socket.socket, session_key: bytes, public_key: RSA.RsaKey | DSA.DsaKey, format: str, p_size: int) -> tuple:
        '''
        Get and return objects from connection according to format
        '''
        # Get size of message to receive
        size_bytes = connection.recv(4)
        size = struct.unpack('I', size_bytes)[0]

        # Receive message over connection
        message = connection.recv(size)

        # Parse message
        nonce, tag, ciphertext, signature = message[:16], message[16:32], message[32:32+p_size], message[32+p_size:]

        # Create AES object for decryption
        cipher = AES.new(session_key, AES.MODE_GCM, nonce)

        # Decrypt and verify ciphertext
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        # Verify digital signature
        DS.verify_dig_sign(SHA1.new(plaintext), signature, public_key)
        
        # Return tuple of objects
        return struct.unpack(format, plaintext)


    def send(connection: socket.socket, session_key: bytes, private_key: RSA.RsaKey | DSA.DsaKey, format: str, *args):
        '''
        Send objects over connection according to format
        '''
        # Create plaintext
        plaintext = struct.pack(format, *args)

        # Create digital signature
        signature = DS.generate_digital_signature(SHA1.new(plaintext), private_key)

        # Create AES cipher object for encryption
        cipher = AES.new(session_key, AES.MODE_GCM)

        # Encrypt and digest plaintext
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        # Create message
        message = cipher.nonce + tag + ciphertext + signature

        # Send message with message length prepended
        connection.send(struct.pack(f'I', len(message)) + message)