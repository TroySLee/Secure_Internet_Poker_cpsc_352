#Dynamic generation and verification of ds's                              

from Cryptodome.Signature import pkcs1_15, DSS
from Cryptodome.PublicKey import RSA, DSA
from Cryptodome.Hash import SHA256

class DigitalSignature:
    '''
    A class for digital signature generation and verification functions
    '''

    def generate_digital_signature(msg_hash: SHA256.SHA256Hash, key: RSA.RsaKey | DSA.DsaKey) -> bytes:
        '''
        Generates the digital signature for some hash given asymmetric key
        '''

        # Given RSAkey
        if type(key) == RSA.RsaKey:
            return pkcs1_15.new(key).sign(msg_hash)
        
        # Given DSAkey
        elif type(key) == DSA.DsaKey:
            return DSS.new(key, 'fips-186-3').sign(msg_hash)
        
        # Unknown key type
        else:
            raise TypeError(f'key type is not supported: ({type(key)})')

    def verify_dig_sign(msg_hash: SHA256.SHA256Hash, signature: bytes, key: RSA.RsaKey | DSA.DsaKey):
        '''
        Verifies the digital signature given hash and asymmetric key
        '''

        # Given RSAkey
        if type(key) == RSA.RsaKey:
            try:
                pkcs1_15.new(key).verify(msg_hash, signature)
                print("Signature is valid.")
            except (ValueError, TypeError):
                print("Signature is invalid.")
        # Given DSAkey
        elif type(key) == DSA.DsaKey:
            try:
                DSS.new(key, 'fips-186-3').verify(msg_hash, signature)
                print("Signature is valid.")
            except (ValueError, TypeError):
                print("Signature is invalid.")
        # Unknown key type
        else:
            raise TypeError(f'key type is not supported: ({type(key)})')