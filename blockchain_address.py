"""
Generating a Blockchain 1 Address


0 - Private ECDSA key
    ***In Bitcoin, a private key is a single unsigned 256 bit integer (32 bytes).***
1 - Generate public key with it (33 bytes, 1 byte 0x02 (y-coord is even), and 32 bytes corresponding to x coordinate)
2 - Perform SHA-256 hashing on public key
3 - Perform RIPEMD-160 hashing on the result of SHA-256
4 - Add version byte in front of RIPEMD-160 hash (0x00 for Main Network for Bitcoin)

Now we do Base58Check encoding

5 - Perform SHA-256 hash on the extended RIPEMD-160 hash
6 - Perform SHA-256 hash on the result of the previous SHA-256 hash
7 - Take the first 4 bytes (32 bits) of the second SHA-256 hash. This is the address checksum 
8 - Add the 4 checksum bytes from stage 7 at the end of the extended RIPEMD-160 hash from stage 4. This is the 25-byte binary Bitcoin Address
9 - Convert the result from a byte string into a base58 string using Base58Check encoding. This is the most commonly used Bitcoin Address format.


We need hashlib to generate the SHA-256 hash.
We need ECDSA (Elliptical Curve Digital Signiture Algorithm) libary for private key derivation.
We need a way to convert byte string into base58 string using Base58Check encoding. base58check pip libary.


Need these functions:
    Generate private key/verifying key (public key) pair
        return verifying key
    Generate a public key based on the private key
        return Bitcoin 1 address
    Function to perform SHA-256 on any input.
        hashlib.sha256()
        return digested hash object
    Function to perform RIPEMD-160 hashing on any input.
        hashlib.new('ripe160')
        return digested hash object
    Function to get the checksum and add it to the RIPEMD-160 hash.
        double_hash()
        return network byte + ripe hash + checksum
    Function to convert the 25-byte binary address into base58 string.
        base58()
        return Bitcoin 1 address


Credit: https://codereview.stackexchange.com/questions/185106/bitcoin-wallet-address-and-private-key-generator/185108
        http://procbits.com/2013/08/27/generating-a-bitcoin-address-with-javascript
        Diego Pino, Toby Speight on stackexchange
        https://github.com/Destiner/blocksmith/blob/master/blocksmith/bitcoin.py


Test: Should Be Same Length
Private Key : 18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725 --> 64 bytes?
              1184CD2CDD640CA42CFC3A091C51D549B2F016D454B2774019C2B2D2E08529FD 
              86c5e7fe1a9a8894d9806a74f0c34d7bb61da4145616908bb7b8ac096d1c5b64

Public Key  : 1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs
              2UcRc6dPTV6LQRePun7cjfzmmtaa6vaBSf2b --> incorrect
              2Ub4psxAjGqN7YanuUUqb5UYDw61W9G34Wmt --> incorrect
              2UcbgSTwMgpYR3afUrcpMkaeP2SEi8REKt6E --> incorrect
              18mhCPFwPokXN8wLMs4KeJfhUdc1i6kcZ6

Ripe Hash   : 3c176e659bea0f29a3e9bf7880c112b1b31b4dc8
              53a071588ce21e2be40f64bdc63c49ce1690f591
              e4770e40f4e059fb46af270cebdf867b7895f8df

Checksum    : 26268187
              2898057c

Unencoded   : 003c176e659bea0f29a3e9bf7880c112b1b31b4dc826268187 
              30783030e4770e40f4e059fb46af270cebdf867b7895f8df771acfb3 --> incorrect

Wallet      : 1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs --> Starts with 1?
              14oC4SS9ZbHN5pgHrnchgtoZVvhE1JkPrH
              1AhVdFp3gtg98fUwZCGKuTP3adJFRqaWJz
"""

import hashlib
import ecdsa
import base58check
import codecs


from ecdsa.keys import SigningKey
from utilitybelt import dev_random_entropy
from binascii import hexlify, unhexlify


def random_secret_exponent(curve_order) -> int:
    """
    This will be our "random" number generator using dev_random_entropy.

    Generates a random hex number by calling the dev_random_entropy function, and then converts that byte data type into hexidecimal.
    Generates a random int between the random entropy hexadecimal and 16.
    If int is between the curve_order and 1 then it will return that int, which will be used as the secret exponent in the private key generation.
    """
    while True:
        random_hex = hexlify(dev_random_entropy(32))
        random_int = int(random_hex, 16)
        if random_int >= 1 and random_int < curve_order:
            return random_int


def generate_private_key():
    """
    () -> hex

    Generate a private key and 
    Return respective public key pair using the Elliptical Curve Digital Signiture Algorithm.
    
    SECP256k1 curve. -> curve
    Generate a 'random' number to use in the generation of the private key. -> se
    Generate the key with the two above inputs and pass it through a SHA-256 hash. -> sha256(key) -> verifying_key
    Return the hexideciaml conversion of verifying key (public key pair to the private key generated) verifying_key -> hex

    This is our private key's public key pair.
    """

    curve = ecdsa.curves.SECP256k1
    se = random_secret_exponent(curve.order)
    key = SigningKey.from_secret_exponent(se, curve, hashlib.sha256)
    verifying_key = key.get_verifying_key()
    verifying_key_string = verifying_key.to_string()
    bitcoin_byte = b'04'
    key_hex = hexlify(key.to_string())
    return hexlify(key.to_string())


def generate_public_key(private_key_hex:bytes):
    """
    (bytes) -> Base58 Bitcoin 1 Address
    Public keys are generated by:
        Q=dG

        where Q is the public key, d is the private key, and G is a curve parameter.
    
    A public key is a 65 byte long value consisting of a leading 0x04 and X and Y coordinates of 32 bytes each.
    
    Pass through a SHA-256 hash method. -> sha256(key)
    Pass through the ripe hash method. -> ripemd160(key)
    Add the version byte in front of the ripe hashed key. -> b'00' + ripemd160
    Calculate the checksum by taking the first 4 bytes of the double SHA-256 hashed ripe hash. -> double_sha256(ripemd160)[first four digits]
    Return the base58 encoding of the extended ripe hash 25-byte address to get the Bitcoin address. -> base58(network byte + ripehash + checksum).

    """
    #Decodes from hex to bytes
    private_key_hex_bytes = codecs.decode(private_key_hex, 'hex')
    #Stores a SHA-256 Hash Object of the private_key above
    pkhb_sha256 = hashlib.sha256(private_key_hex_bytes)
    #Digests the Hash Object into bytes
    pkhb_sha256_digest = pkhb_sha256.digest()

    #Passes SHA-256 hashed private_key into RIPEMD-160 Hash
    pkhb_ripe160 = ripemd160(pkhb_sha256_digest)
    #Encodes the digest into bytes
    pkhb_ripe160_digest_hex = codecs.encode(pkhb_ripe160,'hex')

    #Network byte represents which network, 0x00 for Main Net Bitcoin
    network_byte = b'00'
    #Add the network byte to the RIPE hash key
    pkhb_network_ripe160 = network_byte + pkhb_ripe160_digest_hex

    #Calculate Checksum

    #Double SHA-256
    pkhb_network_ripe160_double_sha256 = double_sha256(pkhb_network_ripe160)
    #Digest encoded to hex 
    pkhb_network_ripe160_double_sha256_digest_hex = codecs.encode(pkhb_network_ripe160_double_sha256, 'hex')
    #First 4 bytes
    checksum = pkhb_network_ripe160_double_sha256_digest_hex[:8]
    #Add checksum to extended RIPEMD-160 hash.
    unencoded_bitcoin_address = (pkhb_network_ripe160 + checksum).decode('utf-8')
    #Base58 Encode
    bitcoin_address = base58(unencoded_bitcoin_address)
    
    #Encode into base58 format. Bitcoin Addresses begin with 1.
    print('First SHA: {},\n RIPEMD-160: {},\n Network Add: {},\n Double SHA: {},\n Checksum: {},\n Unencoded: {},\n Bitcoin Address: {}\n'.format(codecs.encode(pkhb_sha256_digest, 'hex'),
             pkhb_ripe160_digest_hex, 
             pkhb_network_ripe160, 
             pkhb_network_ripe160_double_sha256_digest_hex, 
             checksum, 
             unencoded_bitcoin_address, 
             bitcoin_address))
    return bitcoin_address


def base58(address_hex:str):
    """
    (str) - > str

    Encodes str into Base58.

    Credit to https://github.com/Destiner/blocksmith/blob/master/blocksmith/bitcoin.py
    for this base58 encoder.
    """
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    b58_string = ''
    # Get the number of leading zeros and convert hex to decimal
    leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
    # Convert hex to decimal
    address_int = int(address_hex, 16)
    # Append digits to the start of string
    while address_int > 0:
        digit = address_int % 58
        digit_char = alphabet[digit]
        b58_string = digit_char + b58_string
        address_int //= 58
    # Add '1' for each 2 leading zeros
    ones = leading_zeros // 2
    for one in range(ones):
        b58_string = '1' + b58_string
    return b58_string

    
def double_sha256(key) -> bytes:
    """
    (bytes) -> bytes

    This method will double hash the inputted key using the SHA-256 hashing method.

    Returns the hashed key in bytes format.
    """
    return hashlib.sha256(hashlib.sha256(key).digest()).digest()


def ripemd160(key) -> bytes:
    """
    Input is a SHA-256 private_key_digest.

    Returns digest of ripemd160 Hash Object
    
    The RIPEMD-160 hash is available in the OpenSSL library but not the default hashlib library. The
    hashlib.new() method is used to access this specific hash.
    """
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(key)
    return ripemd160.digest()


def main():
    """
    The method to generate a Bitcoin 1 Address.

    First, calls function to generate private key.
    Second, it calls the function to generate a public key using the private key.
    Third, it will print out both the keys.

    Example of testing using a known private key:
    private_key = '18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725'.encode()

    """

    private_key = generate_private_key()
    public_key = generate_public_key(private_key)
    print("Private Key: {},\n Public Key: {}".format(private_key, public_key))


if __name__ == "__main__":
    main()