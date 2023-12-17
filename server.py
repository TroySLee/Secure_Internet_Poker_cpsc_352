#Server program for the Secure Internet Poker Game                       #

from collections import Counter
from random import randint
from pathlib import Path
import struct
import sys
import ipaddress
import socket

from Cryptodome.PublicKey import RSA, DSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Hash import SHA1

sys.path.append('..')
from mydigitalsignature import DigitalSignature as DS
from message import Message as M


class Server:
    '''
    Server class for Secure Internet Poker Game
    '''
    def __init__(self, server_ip: str, server_port: int):

        # Server Attributes
        self.ip = server_ip
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.ip, server_port))
        self.port = self.socket.getsockname()[1]

        # Public Key Cryptography Attributes
        self.private_key = RSA.import_key(Path('server_rsa_private_key.pem').read_bytes())
        self.public_keys = {
            (1, 'RSA'): RSA.import_key(Path('player1_rsa_public_key.pem').read_bytes()),
            (2, 'RSA'): RSA.import_key(Path('player2_rsa_public_key.pem').read_bytes()),
            (1, 'DSA'): DSA.import_key(Path('player1_dsa_public_key.pem').read_bytes()),
            (2, 'DSA'): DSA.import_key(Path('player2_dsa_public_key.pem').read_bytes())
        }
        self.rsa_cipher = PKCS1_OAEP.new(self.private_key)

        # Client Attributes
        self.clients = {}
        self.player1_score = 0

    def start_game(self) -> None:
        '''
        Start the Secure Internet Poker Game
        
        Steps:
            1. Wait for players to join
            2. Create and distrubute player hands
            3. Wait for players to choose cards
            4. Send round data to players
            5. Repeat steps 3-4 two more times (-3 for last round)
            6. Print final results
            7. End the game
        '''
        
        ### WAIT FOR PLAYERS TO JOIN #######################################################################
        self.accept_players()

        # Gather player info after both players have joined
        player1_conn, player1_session_key, player1_public_key = self.clients[1]
        player2_conn, player2_session_key, player2_public_key = self.clients[2]

        ### CREATE AND DISTRIBUTE PLAYER HANDS #############################################################

        # Create player hands
        player1_hand = [randint(1, 15) for _ in range(3)]
        player2_hand = [randint(1, 15) for _ in range(3)]
        count = Counter(player1_hand + player2_hand)

        # Check for 5 or more identical card numbers
        cont = True
        while cont:
            # For every value in count
            for v in count.values():
                # If count > 4
                if v > 4:
                    # Regenerate hands and try again
                    player1_hand = [randint(1, 15) for _ in range(3)]
                    player2_hand = [randint(1, 15) for _ in range(3)]
                    count = Counter(player1_hand + player2_hand)
                    break
                else:
                    cont = False
                    break

        # Distribute player hands
        try:
            # Send player hands
            M.send(player1_conn, player1_session_key, self.private_key, 'I I I', *player1_hand)
            M.send(player2_conn, player2_session_key, self.private_key, 'I I I', *player2_hand)

        except socket.error:
            self.close_server(f'Error: could not send player hands',
                              player1_conn, player2_conn)

        # Steps 3 and 4 thrice
        #== LOOP STARTS HERE ===============================================================================
        for i in range(3):

            # print round string
            print(f'==================== ROUND {i+1} ====================\n')

            ### WAIT FOR PLAYERS TO CHOOSE CARDS ###########################################################
            
            # Rounds 1 and 2
            if i < 2:
                try:
                    # Print waiting message
                    print('Waiting for players to choose...\n')

                    # Get player choices
                    player1_card = M.get(player1_conn, player1_session_key, player1_public_key, 'I', 4)[0]
                    player2_card = M.get(player2_conn, player2_session_key, player2_public_key, 'I', 4)[0]

                except ValueError:
                    self.close_server(f'Error: could not verify digital signature',
                                    player1_conn, player2_conn)
                    
                except socket.error:
                    self.close_server(f'Error: could not received player cards',
                                    player1_conn, player2_conn)
            # Round 3
            else:
                player1_card = player1_hand[0]
                player2_card = player2_hand[0]

            # Print player cards
            if i < 2:
                print(f'Player1 chose {player1_card} - {player1_hand}')
                print(f'Player2 chose {player2_card} - {player2_hand}\n')
            else:
                print(f"Player1's last card is {player1_card} - {player1_hand}")
                print(f"Player2's last card is {player2_card} - {player2_hand}\n")

            # Validate choice
            if player1_card not in player1_hand or player2_card not in player2_hand:
                self.close_server(f'Error: player card not in hand',
                                  player1_conn, player2_conn)

            # Update player hand
            player1_hand.remove(player1_card)
            player2_hand.remove(player2_card)

            ### SEND ROUND DATA TO PLAYERS #################################################################

            # Determine winner
            # Player 2 wins
            if player1_card == player2_card:
                result = 0
            # Player 1 wins
            elif player1_card > player2_card:
                result = 1
                self.player1_score += 1
            # Tie
            else:
                result = 2
                self.player1_score -= 1

            # Print result
            if result != 0:
                print(f'Player{result} Wins!\n')  
            else:
                print(f"It's a Tie!!\n")

            # Send cards and result to players
            M.send(player1_conn, player1_session_key, self.private_key, 'I I I',
                   player1_card, player2_card, result)
            
            M.send(player2_conn, player2_session_key, self.private_key, 'I I I',
                   player2_card, player1_card, result)

            ################################################################################################
        
        #== LOOP ENDS HERE =================================================================================

        print(f'=================================================\n')

        ### PRINT FINAL RESULTS ############################################################################
        if self.player1_score < 0:
            print(f'PLAYER2 WINS!!!\n')
        elif self.player1_score > 0:
            print(f'PLAYER1 WINS!!!\n')
        else:
            print(f"THE GAME IS A TIE!\n")

        ####################################################################################################

        ### END THE GAME ###################################################################################
        self.close_server(f'Have A Nice Day!!!', player1_conn, player2_conn)

        ####################################################################################################

    
    def accept_players(self) -> None:
        '''Accept client connections until player1 and player2 connect'''

        # Set listening buffer to 2
        self.socket.listen(2)
        print(f'Listening for connections on {self.ip}:{self.port}\n')
        while len(self.clients) < 2:

            # Wait for a client to connect
            conn, addr = self.socket.accept()

            # Client connected 
            print(f'Client connected from {addr}')

            # Recieve client message and obtain session key
            client_message_enc = conn.recv(1024)
            ciphertext, signature = client_message_enc[:256], client_message_enc[256:]

            # Decrypt ciphertext
            plaintext = self.rsa_cipher.decrypt(ciphertext)

            # Parse plaintext
            identity, signature_scheme, session_key = struct.unpack('I 3s 16s', plaintext)
            public_key = self.public_keys[(identity, signature_scheme.decode('utf-8'))]

            # Verify digital signature
            try: DS.verify_dig_sign(SHA1.new(plaintext), signature, public_key)
            except ValueError:
                print(f'Could not verify digital signature')
                print('Closing client connection...\n')
                conn.close()
                continue

            ### Challenge response ###############################################################
            # Try and get nonce
            try: n = M.get(conn, session_key, public_key, 'I', 4)[0]
            except socket.error:
                print(f'Could not get client nonce')
                conn.close()
                continue

            # Try to send f(n) where f(x) = x ** 2
            try: M.send(conn, session_key, self.private_key, 'I', n**2)
            except socket.error:
                print(f'Could not send f(n)')
                conn.close()
                continue
            ######################################################################################

            # Add client to client dictionary
            if identity not in self.clients:
                self.clients[identity] = (conn, session_key, public_key)
                print(f'Player{identity} has connected!\n')
            else:
                print(f'Player{identity} already connected')
                print('Closing client connection...\n')
                conn.close()

    def close_server(self, message: str, player1_conn: socket.socket, player2_conn: socket.socket):
        '''Close connections and terminate program'''

        # Print closing message
        print(f'{message}\nClosing server...')

        # Attempt to close player1 connection
        try: player1_conn.close()
        except socket.error: print(f'Player1 connection already closed')
        else: print('Player1 connection closed...')

        # Attempt to close player2 connection
        try: player2_conn.close()
        except socket.error: print(f'Player2 connection already closed')
        else: print('Player2 connection closed...')

        # Attempt to close server connection
        try: self.socket.close()
        except socket.error: print(f'Could not close server connection\n')
        else: print('Server connection closed...\n\n\n\n')


if __name__ == '__main__':

    print()

    # Ensure correct number of parameters ########################################################
    if len(sys.argv) != 3:
        print('Usage: python server.py SERVER_IP SERVER_PORT\n')
        exit(1)

    # Parse SERVER_IP as IP address
    try: ip = ipaddress.ip_address(sys.argv[1])
    except ValueError:
        # Try parsing as hostname
        try:
            ip_string = socket.gethostbyname(sys.argv[1])
            ip = ipaddress.ip_address(ip_string)
        except socket.gaierror:
            print('Invalid server ip address\n')
            exit(1)

    # Parse SERVER_PORT
    try: port = int(sys.argv[2])
    except ValueError:
        print('Invalid port number\n')
        exit(1)
    if port < 0 or port > 65535:
        print('Invalid port number\n')
        exit(1)

    # Create server and start game
    server = Server(ip.compressed, port)
    server.start_game()