
#Client program for the Secure Internet Poker Game              

from Cryptodome.PublicKey import RSA, DSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Hash import SHA1
from Cryptodome.Random import get_random_bytes

from random import randint
from pathlib import Path
import ipaddress
import socket
import struct
import sys

sys.path.append('..')
from mydigitalsignature import DigitalSignature as DS
from message import Message as M


class Client:
    '''
    Client for Secure Internet Poker Game
    '''

    def __init__(self, player_num: int, hash: str, server_ip: str, server_port: int) -> None:
        # General Attributes
        self.player_num = player_num
        self.hash_name = hash

        # Game Attributes
        self.score = 0
        self.hand = self.card = None

        # Server Attributes
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ip, self.port = server_ip, server_port

        # Symmetric Cryptography Attributes
        self.session_key = get_random_bytes(16)

        # Public Key Cryptography Attributes
        self.private_key = RSA.import_key(Path(f'player{player_num}/player{player_num}_rsa_private_key.pem').read_bytes()) if hash == 'RSA' else \
            DSA.import_key(Path(f'player{player_num}/player{player_num}_dsa_private_key.pem').read_bytes())
        self.server_key = RSA.import_key(Path(f'player{player_num}/server_rsa_public_key.pem').read_bytes())
        self.rsa_cipher_server = PKCS1_OAEP.new(self.server_key)

    def start_game(self) -> None:
        """Start the Secure Internet Poker Game."""
        self.connect_to_server()

        self.send_hello()
        self.challenge_response()
        print(f'Success!!!\n')

        self.hand = list(self.get_player_hand())

        self.play_game()

        print(f'=================================================\n')
        self.print_final_result()

        self.close_client(f'Have A Nice Day!!!')
    def connect_to_server(self) -> None:
        """Connect to the server."""
        try:
            print(f'Connecting to server at {self.ip}:{self.port}')
            self.server_socket.connect((self.ip, self.port))
        except ConnectionRefusedError:
            self.close_client(f'FAILED TO CONNECT!')
        print('Connected...\n')

    def play_game(self) -> None:
        """Play the Secure Internet Poker Game."""
        for i in range(self.NUM_ROUNDS):
            print(f'==================== ROUND {i + 1} ====================\n')

            if i < 2:
                self.choose_card()
                self.send_card_to_server()
                print(f'Waiting for player{3 - self.player_num}...\n')
            else:
                self.card = self.hand[0]

            my_card, opponent_card, result = self.get_cards_and_result()

            self.print_round_result(my_card, opponent_card, result)    
            
    def choose_card(self) -> None:
        """Allow the player to choose a card."""
        print('Please choose a card from your current hand:')
        while True:
            print(f'\tCurrent hand: {self.hand}')

            card = input('Choice: ')

            if not card.isnumeric() or int(card) not in self.hand:
                print(f'{card} not in hand, please try again...\n')
                continue
            else:
                self.card = int(card)
                break
        self.hand.remove(self.card)

    def send_card_to_server(self) -> None:
        """Send the chosen card to the server."""
        try:
            M.send(self.server_socket, self.session_key, self.private_key, 'I', self.card)
        except socket.error:
            self.close_client(f'Error: could not send card') 
    
    def print_round_result(self, my_card, opponent_card, result) -> None:
        """Print the result of a game round."""
        if result == 0:
            print(f"It's a Tie!!\n")
        elif result == self.player_num:
            print(f'You won the round!!!\n')
            self.score += 1
        else:
            print(f'You lost the round.\n')
            self.score -= 1

    def send_hello(self) -> None:
        '''
        Send hello message to server
        '''

        try:
            # Create message
            plaintext = struct.pack('I 3s 16s', self.player_num, self.hash_name.encode('utf-8'), self.session_key)

            # Create digital signature
            signature = DS.generate_digital_signature(SHA1.new(plaintext), self.private_key)

            # Encrypt plaintext
            ciphertext = self.rsa_cipher_server.encrypt(plaintext)

            # Send ciphertext and digital signature to server
            self.server_socket.send(ciphertext + signature)

        except ConnectionError:
            self.close_client(f'Error: Could not send data!!!')

    def challenge_response(self):
        '''
        Do challenge response protocol
        
        Generate and send a nonce. Receive f(nonce) from server and validate it. f(x) = x ** 2
        '''
        # Generate nonce
        nonce = randint(0, 65535)

        # Try to send nonce to server
        try: M.send(self.server_socket, self.session_key, self.private_key, 'I', nonce)
        except socket.error:
            self.close_client(f'Error: Could not send nonce to server')

        # Try and get nonce ** 2 from server
        try: f_nonce = M.get(self.server_socket, self.session_key, self.server_key, 'I', 4)[0]
        except socket.error:
            self.close_client(f'Error: Could not get f(nonce) from server')

        # Ensure matching values
        if nonce ** 2 != f_nonce:
            self.close_client(f'Error: f(nonce) does not match')

    def get_cards_and_result(self) -> tuple[3]:
        '''
        Get and validate cards and result from server
        '''

        # Attempt to get cards and result from server
        try: player_card, opponent_card, result = M.get(self.server_socket, self.session_key, self.server_key, 'I I I', 12)
        except socket.error:
            self.close_client(f'Error: could not get cards')
        except ValueError:
            self.close_client(f'Error: could not verify digital signature')

        # Validate player card
        if player_card != self.card:
            self.close_client(f'Error: Card does not match')

        # Determine result based on supplied cards
        if player_card == opponent_card:
            my_result = 0
        elif player_card > opponent_card:
            my_result = self.player_num
        else:
            my_result = 2 if self.player_num == 1 else 1

        # Verify result
        if my_result != result:
            self.close_client(f'Error: Discrepancy in results')

        # Return cards and result
        return player_card, opponent_card, result

    def close_client(self, message: str) -> None:
        '''
        Close the client and exit program
        '''

        # print closing message
        print(f'{message}\n\nClosing client . . .\n\n\n\n')

        # close socket and exit
        self.server_socket.close()
        exit(1)

 
if __name__ == '__main__':

    print()

    # Ensure correct number of parameters ########################################################
    if len(sys.argv) != 5:
        print('Usage: python client.py PLAYER_NUMBER DGST_SCHEME SERVER_IP SERVER_PORT\n')
        exit(1)

    # Parse PLAYER_NUMBER ########################################################################
    try: 
        num = int(sys.argv[1])
        if num not in (1, 2):
            raise ValueError
    except ValueError:
        print('Invalid player number (accepts 1 or 2)\n')
        exit(1)

    # Parse DGST_SCHEME ##########################################################################
    if sys.argv[2].upper() not in ('RSA', 'DSA'):
        print("Invalid digital signature scheme (accepts 'RSA' or 'DSA')\n")
        exit(1)
    hash = sys.argv[2].upper()

    # Parse SERVER_IP as IP address ##############################################################
    try: ip = ipaddress.ip_address(sys.argv[3])
    except ValueError:
        # Try parsing as hostname 
        try:
            ip_string = socket.gethostbyname(sys.argv[3])
            ip = ipaddress.ip_address(ip_string)
        except socket.gaierror:
            print('Invalid server ip address\n')
            exit(1)

    # Parse SERVER_PORT ##########################################################################
    try: port = int(sys.argv[4])
    except ValueError:
        print('Invalid port number\n')
        exit(1)
    if port < 0 or port > 65535:
        print('Invalid port number\n')
        exit(1)

    # Create Client ##############################################################################
    player = Client(num, hash, ip.compressed, port)

    # Start Game #################################################################################
    player.start_game()
