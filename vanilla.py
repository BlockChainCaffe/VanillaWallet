#!/usr/bin/python3

"""
    Vanilla Wallet: a multi currency cold store wallet

    Supported currencies:
        Bitcoin 
            legacy, bech32, segwith
        Ethereum

    NOTE:
        This code is provided  ​“AS IS” with all faults, defects, bugs, and errors. 
        Developers, authors  and mantainers of the code makes no warranties, express
        or implied, and hereby disclaims all implied warranties, including any 
        warranty of merchantability and warranty of fitness for a particular purpose.
        Use it at your own risk. 
        Developers, authors  and mantainers cannot be held responsible for any damage 
        or loss deriving from the use of this code

    Why vanilla?
        vanilla stands for "simple & plain", also is an ingredient for iced coffe :)

    Credits:
        - Massimo S. Musumeci massmux https://github.com/massmux/bip39gen
        - MaxP

    Licence:
        GNU General Public Licence V3

    Tested against:
        https://privatekeys.pw

"""


### Imports
import sys
import argparse
from sty import fg, bg, ef, rs
import subprocess

import bit
from bit import utils
from mnemonic import Mnemonic
from web3 import Web3
import bech32
import base58

import binascii
from binascii import hexlify, unhexlify
import hashlib


### Globlals & Constants 

MIC_RND_SEC = 30        # seconds of mic sampling for private key generation
SHA_RND_RND = 2048      # number of sha256 rounds for private key generation
MIC_SLT_SEC = 5         # seconds of mic sampling for salt


Args = {}
PrivateKey = 0
PublicKey = 0
BIP39Words = ""


### Minor Helper functions

def getsha256(z):
    return hashlib.sha256(z.encode('utf-8')).hexdigest()


###
###    MAIN
###


def generatePrivateKey():
    global PrivateKey

    if (Args.entropy):
        # accept and use entropy string provided by user instead of mic one
        # print("You provided the entropy as a string")
        hash0=getsha256(Args.entropy)
        # print("256bits hash from your source: %s" % hash0)
        salt0=""
    else:
        # create random by reading the mic for rnd_len seconds
        print("Getting entropy from %s secs mic audiorecording... Please wait" % str(MIC_RND_SEC) )
        mycmd=subprocess.getoutput('arecord -d %s -f dat -t wav -q | sha256sum -b' %  str(MIC_RND_SEC) )
        hash0=mycmd[:64]
        # print("256bits hashed entropy: %s" % hash0)
        # create random for salt
        print("Getting entropy from mic for creating a salt... Please wait" )
        mysalt=subprocess.getoutput('arecord -d %s -f dat -t wav -q | sha256sum -b' %  str(MIC_SLT_SEC) )
        salt0=mysalt[:64]
        # print("256bits hashed salt: %s" % salt0)

    """ sha256 rounds """
    print ("Iterating %s rounds of salted sha256 hashing... Please wait" % SHA_RND_RND )
    for i in range(0,SHA_RND_RND):
        hash0=getsha256(hash0+salt0)
        #debug purpose
        # print("%s %s Round %s val %s" % (hash0,salt0,i , hash0))

    PrivateKey = hash0


def generateBIP39Words():
    global BIP39Words
    mnemo = Mnemonic(Args.language)
    byte_array = bytearray.fromhex(PrivateKey)
    BIP39Words = mnemo.to_mnemonic(byte_array)

def restoreWallet():
    global BIP39Words
    global Args
    global PrivateKey
    mnemo = Mnemonic(Args.language)
    BIP39Words = Args.restore
    ent = mnemo.to_entropy(BIP39Words)
    PrivateKey = hexlify(ent).decode("utf-8")

def hash160(pubKey):
    """
        Given a public key (can be hex string or bytes) returns the RIPMED(SHA256(pub))
        Returns the hash160 in bytes (or False on error)
    """
    # trasnform all in bytes
    if (type(pubKey) == str):
        pubKey = bytes.fromhex(pubKey)
    if (type(pubKey) != bytes):
        print(type(pubKey))
        return False
    # compute RIPMED(SHA256(pub))
    hashkey = hashlib.sha256(pubKey).digest()
    ripemd160 = hashlib.new("ripemd160")
    ripemd160.update(hashkey)
    h160 = ripemd160.digest()
    return h160

def pub2bitaddr(version, pubKey):
    """ 
        Creates the address from the public key
        "Bitcoin Stye" : 
            do ripmed(sha)
            add version byte
            add 4 bytes of check
            return in base58
    """
    h160 = hash160(pubKey)
    if not h160:
        return False
    # Add version to the public key (hex)
    ver = version + h160.hex()
    # compute the double sha256 control
    check = hashlib.sha256(hashlib.sha256(bytes.fromhex(ver)).digest()).hexdigest()
    # compose : version + publickey + first 8 bytes of check 
    vercheck = ver + check[:8]
    # encode in base58
    addr = base58.b58encode(bytes.fromhex(vercheck))
    return addr.decode("utf-8")


def main():    

    # Create ECDSA private key
    key = bit.PrivateKeyTestnet.from_hex(PrivateKey) if Args.testnet else bit.Key.from_hex(PrivateKey)

    # get hash160 of public key
    h160 = hash160(key.public_key)

    ## DISPLAY RESULTS
    print(bg(255, 255, 255)+ef.bold+"    Seed     "+rs.bg+rs.bold_dim)
    print("\tPrivate key: ", key.to_hex())
    ## Public key
    # the first byte is to identify if it's in compressed or uncompressed format
    # compressed format uses only X coordinates of public point
    print("\tPublic key   ", key._pk.public_key.format(compressed=False).hex(), " (uncompressed)")
    # uncompressed format uses both X and Y coordinates of public point
    print("\tPublic key:  ", key.public_key.hex(), "(Secp256k1 compressed)")
    print("\tBIP39 Seed:  ", BIP39Words)
    # for idx, word in enumerate(BIP39Words.split(" ")):
    #     if ((idx+1) % 6 == 1):
    #         print("\n\t\t\t", end="")
    #     print("{:2}){:12}\t".format(idx+1,word), end="")


    # Bitcoin
    print()
    print(bg(255, 150, 50)+ef.bold+"   Bitcoin   "+rs.bg+rs.bold_dim)
    print("\tHash160:     ", h160.hex(), "(ripmed160(sha256(pub)))")
    print("\tWIF:         ", key.to_wif())
    print("\tAddress:     ", key.address, " (P2PKH)")
    print("\tSegWit Addr: ", key.segwit_address)
    bech = bech32.encode('tb', 0, h160) if Args.testnet else bech32.encode('bc', 0, h160) 
    print("\tBech32 Addr: ", bech)

    # Ethereum
    print()
    print(bg(150, 150, 150)+ef.bold+"   Ethereum  "+rs.bg+rs.bold_dim)
    # get the uncompressed public key (remove first byte and concat X and Y) 
    pu = key._pk.public_key.format(compressed=False).hex()[2:]
    # hash uncompressed public key with keccak algorithm
    k = Web3.keccak(hexstr=pu)
    # add "0x" at the beginning to show it's hex, the get the last 20 bytes of it
    addr = "0x"+k.hex()[-40:]
    # Turn in into CheCKSuM addresse format (case sensitive)
    addr = Web3.toChecksumAddress(addr)
    print("\tAddress:     ", addr)
    
    # Dash
    print()
    print(bg(50, 50, 255)+ef.bold+"     Dash    "+rs.bg+rs.bold_dim )
    # Address generation is same as Bitcoin, it only changes the version byte
    if Args.testnet:
        addr = pub2bitaddr("8c", key.public_key)
        print("\tAddress:     ", addr, " (P2PKH)")
        addr = pub2bitaddr("13", key.public_key)
        print("\tAddress:     ", addr, " (P2SH)")
    else: 
        addr = pub2bitaddr("4c", key.public_key)
        print("\tAddress:     ", addr, " (P2PKH)")
        addr = pub2bitaddr("10", key.public_key)
        print("\tAddress:     ", addr, " (P2SH)")


    # LiteCoin
    print()
    print(bg(100, 100, 100)+ef.bold+"   Litecoin  "+rs.bg+rs.bold_dim )
    # Address generation is same as Bitcoin, it only changes the version byte
    if Args.testnet:
        addr = pub2bitaddr("6f", key.public_key)
        print("\tAddress:     ", addr, " (P2PKH)")
    else: 
        addr = pub2bitaddr("30", key.public_key)
        print("\tAddress:     ", addr, " (P2PKH)")
    if not Args.testnet:
        bech = bech32.encode('ltc', 0, h160) 
        print("\tBech32 Addr: ", bech)


def parseArguments():
    global Args
    """ parsing arguments """
    parser = argparse.ArgumentParser("Vanilla Wallet command line arguments")
    parser.add_argument("-e", "--entropy", help="An optional random string in case you prefer providing your own entropy", type=str, required=False)
    parser.add_argument("-l", "--language", help="Optional, the language for the mnemonic words list (BIP39). Default: english", type=str, required=False, default="english", choices=["english", "chinese_simplified", "chinese_traditional", "french", "italian", "japanese", "korean", "spanish"])
    parser.add_argument("-t", "--testnet", help="Generate addresses for test net (default is main net)", dest='testnet', action='store_const', const=True, default=False)
    parser.add_argument("-r", "--restore", help="Restore a wallet from BIP39 word list", dest="restore", type=str, required=False)
    Args = parser.parse_args()
    

###
###    START
###

if sys.version_info[0] < 3:
    raise Exception("Python 3 or a more recent version is required.")

if __name__ == "__main__": 
    parseArguments()
    if (Args.restore):
        restoreWallet()
    else :
        generatePrivateKey()
    generateBIP39Words()
    main()
