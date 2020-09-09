#!/usr/bin/python3

"""
    Vanilla Wallet: a multi currency cold store wallet

    Supported currencies:
        Bitcoin 
            legacy, bech32, segwith
        Ethereum
            ETH, Classic, Quadrans
        Litecoin
        Dash

    NOTE:
        This code is provided "AS IS" with all faults, defects, bugs, and errors.
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
        https://learnmeabitcoin.com/technical/wif
        https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki
        https://www.bitaddress.org/

"""


### Imports
import sys
import argparse
import subprocess
import json
import re
from sty import fg, bg, ef, rs
import sounddevice as sd

import bit
from bit import utils
from mnemonic import Mnemonic
from web3 import Web3
import eth_keyfile
import bech32
import base58
# import scrypt
# from Crypto.Cipher import AES
from graphenebase import PrivateKey
from graphenebase.bip38 import encrypt

import binascii
from binascii import hexlify, unhexlify
import hashlib


### Globlals & Constants 

MIC_RND_SEC = 30        # seconds of mic sampling for private key generation
SHA_RND_RND = 2048      # number of sha256 rounds for private key generation
MIC_SLT_SEC = 5         # seconds of mic sampling for salt
SAMPLE_RATE = 44100     # rate of sampling for audio recording 

Args = {}               # Parameters received from command line argiments
dataDict={}             # Dictionaries of values to share between BC address creation functions (RORO approach)


####################################################################################################
##
## HELPER FUNCTIONS
##

def getNoise(sec):
    sound = sd.rec(int(SAMPLE_RATE * sec), samplerate=SAMPLE_RATE, channels=2, blocking=True)
    return hashlib.sha256(bytearray(b''.join(sound))).hexdigest()


####################################################################################################
##
## KEY MANAGEMENT FUNCTIONS
##

def generatePrivateKey():
    global dataDict
    if (Args.entropy):
        # accept and use entropy string provided by user instead of mic one
        # print("You provided the entropy as a string")
        hash0=hashlib.sha256(Args.entropy.encode('utf-8')).hexdigest()
        # print("256bits hash from your source: %s" % hash0)
        salt0=""
    else:
        # create random by reading the mic for rnd_len seconds
        print("Getting entropy from %s secs mic audio recording... Please wait (and make some noise)" % str(MIC_RND_SEC) )
        hash0=getNoise(MIC_RND_SEC)

        # create random for salt
        print("Getting salt from %s secs mic audio recording... Please wait (and make some noise)" % str(MIC_SLT_SEC))
        salt0=getNoise(MIC_SLT_SEC)

    """ sha256 rounds """
    print ("Iterating %s rounds of salted sha256 hashing... Please wait" % SHA_RND_RND )
    for i in range(0,SHA_RND_RND):
        hash0=hashlib.sha256((hash0+salt0).encode('utf-8')).hexdigest()


    # Store raw private key
    dataDict["privateKey"] = hash0
    # Create ECDSA private key
    dataDict["bitcoinKey"] = bit.PrivateKeyTestnet.from_hex(dataDict["privateKey"]) if Args.testnet else bit.Key.from_hex(dataDict["privateKey"])


def deriveBIP39Words():
    global dataDict
    mnemo = Mnemonic(Args.language)
    byte_array = bytearray.fromhex(dataDict["privateKey"])
    dataDict["BIP39Words"] = mnemo.to_mnemonic(byte_array)


def derivePublic():
    key = bit.PrivateKeyTestnet.from_hex(dataDict["privateKey"]) if Args.testnet else bit.Key.from_hex(dataDict["privateKey"])
    dataDict["publicKey"] = key.public_key
    dataDict["publicKey_uncompressed"] = key._pk.public_key.format(compressed=False)


def restoreWallet():
    global dataDict
    global Args
    mnemo = Mnemonic(Args.language)
    dataDict["BIP39Words"] = Args.restore
    ent = mnemo.to_entropy(dataDict["BIP39Words"])
    dataDict["privateKey"] = hexlify(ent).decode("utf-8")


def hash160():
    """
        Given a public key (can be hex string or bytes) returns the RIPMED(SHA256(pub))
        Returns the hash160 in bytes (or False on error)
    """
    global dataDict
    hashkey = hashlib.sha256(dataDict["publicKey"]).digest()
    ripemd160 = hashlib.new("ripemd160")
    ripemd160.update(hashkey)
    h160 = ripemd160.digest()
    dataDict["hash160"] = h160


def pub2bitaddr(version, pubKey):
    """ 
        Creates the address from the public key
        "Bitcoin Stye" : 
            do ripmed(sha)
            add version byte
            add 4 bytes of check
            return in base58
    """
    if not dataDict["hash160"]:
        return False
    # Add version to the public key (hex)
    ver = version + dataDict["hash160"].hex()
    # compute the double sha256 control
    check = hashlib.sha256(hashlib.sha256(bytes.fromhex(ver)).digest()).hexdigest()
    # compose : version + publickey + first 8 bytes of check 
    vercheck = ver + check[:8]
    # encode in base58
    addr = base58.b58encode(bytes.fromhex(vercheck))
    return addr.decode("utf-8")


def deriveWIF(prefix, compressed):
    """ 
        WIF Generation
        Create WIF (Wallet Improt Format) for 
        Bitcoin-like wallets
    """
    exk = prefix + dataDict["privateKey"]
    if compressed :
        exk = exk + "01"
    cks = hashlib.sha256(hashlib.sha256(bytes.fromhex(exk)).digest()).hexdigest()[:8]
    csk = exk+cks
    wif = base58.b58encode(bytes.fromhex(csk)).decode("utf-8")
    return wif

def deriveBIP38():
    if Args.password == None:
        return "Cannot generate BIP38 encrypted key, no password provided. Use '-p' or '--password'"
    privkey = dataDict["privateKey"]
    passphrase = Args.password
    return format(encrypt(PrivateKey(privkey),passphrase), "encwif")


####################################################################################################
##
## RESULT PRINTING FUNCTIONS
##

def banner(color, name):
    """
        Print a banner with a color and name of the coin
    """
    print()
    bgc = bg(color) if isinstance(color,str) else bg(*color)
    print(bgc + ef.bold + "{:^20}".format(name) + rs.bg + rs.bold_dim)


def printBitcoinWallet():
    banner((255, 150, 50), "Bitcoin")
    """
        Print Bitcoin Wallet data:
            Hash160, WIF, BIP38, Address, SegWit Addr, Bech32 Addr
    """
    # Bitcoin
    key = dataDict["bitcoinKey"]

    print("\tHash160:     ", dataDict["hash160"].hex(), "(ripmed160(sha256(pub)))")
    # print("\tWIF:         ", key.to_wif())
    prefix = "EF" if Args.testnet else "80"
    print("\tWIF:         ", deriveWIF(prefix, True))
    if Args.password != None:
        print("\tBIP38:       ", deriveBIP38(), "(encrypted private key)")
    print("\tAddress:     ", key.address, " (P2PKH)")
    print("\tSegWit Addr: ", key.segwit_address)
    bech = bech32.encode('tb', 0, dataDict["hash160"]) if Args.testnet else bech32.encode('bc', 0, dataDict["hash160"]) 
    print("\tBech32 Addr: ", bech)


def deriveEVMaddress():
    # get the uncompressed public key (remove first byte and concat X and Y) 
    pu = dataDict["publicKey_uncompressed"].hex()[2:]
    # hash uncompressed public key with keccak algorithm
    k = Web3.keccak(hexstr=pu)
    # add "0x" at the beginning to show it's hex, the get the last 20 bytes of it
    addr = "0x"+k.hex()[-40:]
    # Turn in into CheCKSuM addresse format (case sensitive)
    return Web3.toChecksumAddress(addr)

def deriveUTCJSON():
    if Args.password == None:
        return "Cannot generate JSON-UTC file, no password provided. Use '-p' or '--password'"
    juct = eth_keyfile.create_keyfile_json(bytes.fromhex(dataDict["privateKey"]), Args.password.encode("utf-8"))
    return  re.sub(r'^|\n'  ,'\n\t\t'  , json.dumps(juct,indent=4))


def printEthereumWallet():
    banner((150, 150, 150),"Ethereum")
    """
        Print Ethereum Wallet data:
            Address:
    """
    print("\tAddress:     ", deriveEVMaddress())
    if Args.password != None:
        print("\tUTC-JSON:    ", deriveUTCJSON())


def printEthereumClassicWallet():
    banner((0, 150, 0),"EthereumClassic")
    """
        Print Ethereum Wallet data:
            Address:
    """
    print("\tAddress:     ", deriveEVMaddress())
    if Args.password != None:
        print("\tUTC-JSON:    ", deriveUTCJSON())


def printQuadransWallet():
    banner((150, 0, 150),"Quadrans")
    """
        Print Ethereum Wallet data:
            Address:
    """
    print("\tAddress:     ", deriveEVMaddress())
    if Args.password != None:
        print("\tUTC-JSON:    ", deriveUTCJSON())


def printDashWallet():
    banner((50, 50, 255),"Dash")
    """
        Print Dash Wallet data:
	        Address: (P2PKH)
	        Address: (P2SH)
    """
    prefix = "EF" if Args.testnet else "CC"
    wif = deriveWIF(prefix, True)
    print("\tWIF:         ", wif)

    # Address generation is same as Bitcoin, it only changes the version byte
    addrP2PKH = pub2bitaddr("8c", dataDict["publicKey"]) if Args.testnet else pub2bitaddr("4c", dataDict["publicKey"]) 
    print("\tAddress:     ", addrP2PKH, " (P2PKH)")
    addrP2SH = pub2bitaddr("13", dataDict["publicKey"]) if Args.testnet else pub2bitaddr("10", dataDict["publicKey"])
    print("\tAddress:     ", addrP2SH, " (P2SH)")


def printLiteCoinWallet():
    banner((100, 100, 100),"Litecoin")
    """
        Print Litecoin Wallet data:
	        Address: (P2PKH)
	        Bech32 Addr:
    """
    prefix = "EF" if Args.testnet else "B0"
    wif = deriveWIF(prefix, True)
    print("\tWIF:         ", wif)
    # Address generation is same as Bitcoin, it only changes the version byte
    addr = pub2bitaddr("6f", dataDict["publicKey"]) if Args.testnet else pub2bitaddr("30", dataDict["publicKey"])
    print("\tAddress:     ", addr, " (P2PKH)")
    if not Args.testnet:
        bech = bech32.encode('ltc', 0, dataDict["hash160"]) 
        print("\tBech32 Addr: ", bech)


####################################################################################################
##
## RESULT PRINTING FUNCTIONS
##


def main():    
    global dataDict
    global Args

    ## DISPLAY RESULTS
    banner("white","Seed")
    print("\tPrivate key: ", dataDict["privateKey"])
    ## Public key
    # the first byte is to identify if it's in compressed or uncompressed format
    # compressed format uses only X coordinates of public point
    print("\tPublic key   ", dataDict["publicKey"].hex(), " (Secp256k1 compressed)")
    # uncompressed format uses both X and Y coordinates of public point
    print("\tPublic key:  ", dataDict["publicKey_uncompressed"].hex(), " (uncompressed)")

    if Args.wordlist:
        print("\tBIP39 Seed:     ", end="")
        for idx, word in enumerate(dataDict["BIP39Words"].split(" ")):
            print("{:2}){:12}\t".format(idx+1,word), end="")
            if ((idx+1) % 6 == 0):
                print("\n\t\t\t", end="")
    else: 
        print("\tBIP39 Seed:  ", dataDict["BIP39Words"])

    if Args.blockchain in ["all","Bitcoin", "btc", "xbt"]:
        printBitcoinWallet()

    if Args.blockchain in ["all","Ethereum", "eth"]:
        printEthereumWallet()

    if Args.blockchain in ["all","EthereumClassic", "etc"]:
        printEthereumClassicWallet()

    if Args.blockchain in ["all","Quadrans", "qdc"]:
        printQuadransWallet()

    if Args.blockchain in ["all","Dash", "dash"]:
        printDashWallet()

    if Args.blockchain in ["all","Litecoin", "ltc"]:
        printLiteCoinWallet()



def parseArguments():
    global Args
    """ parsing arguments """
    parser = argparse.ArgumentParser("Vanilla Wallet command line arguments")
    parser.add_argument("-bc", "--blockchain", help="Optional, the blockchain the wallet is generater for. Default: all", 
        type=str, required=False, default="all",
        choices=[
            "all",
            "Bitcoin", "btc", "xbt", 
            "Litecoin", "ltc",
            "Ethereum", "eth",
            "EthereumClassic", "etc",
            "Quadrans", "qdc",
            "Dash", "dash"
            ])


    parser.add_argument("-wn", "--wordnumber", help="Optional, print BIP39 word list in numbered table", dest='wordlist', action='store_const', const=True, default=False)
    parser.add_argument("-e", "--entropy", help="An optional random string in case you prefer providing your own entropy", type=str, required=False)
    parser.add_argument("-l", "--language", help="Optional, the language for the mnemonic words list (BIP39). Default: english", type=str, required=False, default="english", choices=["english", "chinese_simplified", "chinese_traditional", "french", "italian", "japanese", "korean", "spanish"])
    parser.add_argument("-t", "--testnet", help="Generate addresses for test net (default is main net)", dest='testnet', action='store_const', const=True, default=False)
    parser.add_argument("-r", "--restore", help="Restore a wallet from BIP39 word list", dest="restore", type=str, required=False)
    parser.add_argument("-p", "--password", help="Password for wallet encryption", dest="password", type=str, required=False)

    ## Yet to be implemented
    parser.add_argument("-j", "--json", help="Produce only json output", dest='json', action='store_const', const=True, default=False)
    parser.add_argument("-d", "--directory", help="An optional where to save produced files (json and qr codes)", type=str, required=False, default=".")
    parser.add_argument("-q", "--qrcode", help="Generate qrcodes for addresses and keys", dest='qrcode', action='store_const', const=True, default=False)

    Args = parser.parse_args()


####################################################################################################
###
###    START
###


if sys.version_info[0] < 3:
    raise Exception("Python 3 or a more recent version is required.")

if __name__ == "__main__": 
    # What does the user want?
    parseArguments()

    # Are we on linux -> can we use the mic for entropy?
    # pltfrm_name=sys.platform
    # if(pltfrm_name!="linux") and (not Args.entropy):
    #     print(" The entropy input by mic audio recording can be used only on Linux System" )
    #     print(" Use the -e option to pass a string for entropy" )
    #     exit()

    # How to generate private key?
    if (Args.restore):
        restoreWallet()
    else :
        generatePrivateKey()
    # Gather other data
    deriveBIP39Words()
    derivePublic()
    hash160()

    main()

