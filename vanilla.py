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

    _NOTE:
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
        - Franco

    Licence:
        GNU General Public Licence V3

    Tested against:
        https://privatekeys.pw
        https://learnmeabitcoin.com/technical/wif
        https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki
        https://www.bitaddress.org/

"""

### Imports
import sys, os
import argparse
import subprocess
import json
import re
import io
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

import pdfwallet as pdfw

### Globlals & Constants 

MIC_RND_SEC = 30        # seconds of mic sampling for private key generation
SHA_RND_RND = 2048      # number of sha256 rounds for private key generation
MIC_SLT_SEC = 5         # seconds of mic sampling for salt
SAMPLE_RATE = 44100     # rate of sampling for audio recording 

Args = {}               # Parameters received from command line argiments
dataDict={}             # Dictionaries of values to share between BC address creation functions (RORO approach)

JOut={}                 # JSON Output Object

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
    
    spinner="-\|/"

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
    print ("Iterating %s rounds of salted sha256 hashing..." % SHA_RND_RND )
    for i in range(0,SHA_RND_RND):
        hash0=hashlib.sha256((hash0+salt0).encode('utf-8')).hexdigest()
    print()

    # Store raw private key
    dataDict["privateKey"] = hash0
    

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
    # Store raw private key
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

def deriveEVMaddress():
    # get the uncompressed public key (remove first byte and concat X and Y) 
    pu = dataDict["publicKey_uncompressed"].hex()[2:]
    # hash uncompressed public key with keccak algorithm
    k = Web3.keccak(hexstr=pu)
    # add "0x" at the beginning to show it's hex, the get the last 20 bytes of it
    addr = "0x"+k.hex()[-40:]
    # Turn in into CheCKSuM addresse format (case sensitive)
    return Web3.toChecksumAddress(addr)

def deriveUTCJSON(indent = True):
    if Args.password == None:
        return "Cannot generate JSON-UTC file, no password provided. Use '-p' or '--password'"
    jutc= eth_keyfile.create_keyfile_json(bytes.fromhex(dataDict["privateKey"]), Args.password.encode("utf-8"))
    
    if indent:
        return  re.sub(r'^|\n'  ,'\n\t\t'  , json.dumps(jutc,indent=4))
    else:
        return jutc

def EVMJson():
    eth = {}
    eth['address'] = deriveEVMaddress()
    if Args.password != None:
        eth['UTC-JSON'] = deriveUTCJSON(False)
    return eth

####################################################################################################
##
## RESULT JSON EXPORTING FUNCTIONS
##

def jsonExportPrivate():
    global JOut
    private = {}
    private['privateKey']=dataDict["privateKey"]
    private['publicKey']=dataDict["publicKey"].hex()
    private['publicKeyUncompressed']=dataDict["publicKey_uncompressed"].hex()
    private['bip39words']=dataDict["BIP39Words"]
    private['network'] = "testnet" if Args.testnet else "main"
    JOut['wallet'] = {}
    JOut['keys'] = private

def jsonExportBitcoinWallet():
    global JOut
    bitcoin = {}
    
    # Create ECDSA private key
    key = bit.PrivateKeyTestnet.from_hex(dataDict["privateKey"]) if Args.testnet else bit.Key.from_hex(dataDict["privateKey"])
    bitcoin['hash160']=dataDict["hash160"].hex()
    prefix = "EF" if Args.testnet else "80"
    bitcoin['WIF']=deriveWIF(prefix, True)
    if Args.password != None:
            bitcoin['BIP38']=deriveBIP38()
    bitcoin['address']=key.address
    bitcoin['segwitAddress']=key.segwit_address
    bitcoin['bech32'] = bech32.encode('tb', 0, dataDict["hash160"]) if Args.testnet else bech32.encode('bc', 0, dataDict["hash160"]) 
    bitcoin['network'] = "testnet" if Args.testnet else "main"

    JOut['wallet']['bitcoin'] = bitcoin


def jsonExportEthereumWallet():
    global JOut
    JOut['wallet']['ethereum'] = EVMJson()


def jsonExportEthereumClassicWallet():
    global JOut
    JOut['wallet']['ethereumClassic'] = EVMJson()


def jsonExportQuadransWallet():
    global JOut
    JOut['wallet']['quadrans'] = EVMJson()


def jsonExportDashWallet():
    global JOut
    dash = {}
    prefix = "EF" if Args.testnet else "CC"
    dash['network'] = "testnet" if Args.testnet else "main"
    dash['WIF'] = deriveWIF(prefix, True)

    # Address generation is same as Bitcoin, it only changes the version byte
    dash['addrP2PKH'] = pub2bitaddr("8c", dataDict["publicKey"]) if Args.testnet else pub2bitaddr("4c", dataDict["publicKey"]) 
    dash['addrP2SH'] = pub2bitaddr("13", dataDict["publicKey"]) if Args.testnet else pub2bitaddr("10", dataDict["publicKey"])
    JOut['wallet']['dash'] = dash


def jsonExportLiteCoinWallet():
    global JOut
    lite = {}
    prefix = "EF" if Args.testnet else "B0"
    lite['WIF'] = deriveWIF(prefix, True)
    # Address generation is same as Bitcoin, it only changes the version byte
    lite['address'] = pub2bitaddr("6f", dataDict["publicKey"]) if Args.testnet else pub2bitaddr("30", dataDict["publicKey"])
    if not Args.testnet:
        lite['bech32'] = bech32.encode('ltc', 0, dataDict["hash160"])
    lite['network'] = "testnet" if Args.testnet else "main"
    JOut['wallet']['litecoin'] = lite


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


def printSeed():
    ## DISPLAY RESULTS TO STDOUT
    banner("white","Seed")
    print("\tPrivate key: ", JOut['keys']['privateKey'])
    print("\tPublic key   ", JOut['keys']['publicKey'], " (Secp256k1 compressed)")
    print("\tPublic key:  ",JOut['keys']['publicKeyUncompressed'], " (uncompressed)")

    if Args.wordlist:
        print("\tBIP39 Seed:     ", end="")
        for idx, word in enumerate(JOut['keys']['bip39words'].split(" ")):
            print("{:2}){:12}\t".format(idx+1,word), end="")
            if ((idx+1) % 6 == 0):
                print("\n\t\t\t", end="")
    else: 
        print("\tBIP39 Seed:  ", JOut['keys']['bip39words'])


def printBitcoinWallet():
    banner((255, 150, 50), "Bitcoin")
    print("\tNetwork:     ", JOut['wallet']['bitcoin']['network'])
    print("\tHash160:     ", JOut['wallet']['bitcoin']['hash160'], "(ripmed160(sha256(pub)))")
    print("\tWIF:         ", JOut['wallet']['bitcoin']['WIF'])
    if Args.password != None:
        print("\tBIP38:       ", JOut['wallet']['bitcoin']['BIP38'], "(encrypted private key)")
    print("\tAddress:     ", JOut['wallet']['bitcoin']['address'], " (P2PKH)")
    print("\tSegWit Addr: ", JOut['wallet']['bitcoin']['segwitAddress'])
    print("\tBech32 Addr: ", JOut['wallet']['bitcoin']['bech32'])


def printEthereumWallet():
    banner((150, 150, 150),"Ethereum")
    print("\tAddress:     ", JOut['wallet']['ethereum']['address'])
    if Args.password != None:
        print("\tUTC-JSON:    ", deriveUTCJSON())


def printEthereumClassicWallet():
    banner((0, 150, 0),"EthereumClassic")
    print("\tAddress:     ", JOut['wallet']['ethereumClassic']['address'])
    if Args.password != None:
        print("\tUTC-JSON:    ", deriveUTCJSON())


def printQuadransWallet():
    banner((150, 0, 150),"Quadrans")
    print("\tAddress:     ", JOut['wallet']['quadrans']['address'])
    if Args.password != None:
        print("\tUTC-JSON:    ", deriveUTCJSON())


def printDashWallet():
    banner((50, 50, 255),"Dash")
    print("\tNetwork:     ", JOut['wallet']['dash']['network'])
    print("\tWIF:         ", JOut['wallet']['dash']['WIF'])
    print("\tAddress:     ", JOut['wallet']['dash']['addrP2PKH'], " (P2PKH)")
    print("\tAddress:     ", JOut['wallet']['dash']['addrP2SH'], " (P2SH)")


def printLiteCoinWallet():
    banner((100, 100, 100),"Litecoin")
    print("\tNetwork:     ", JOut['wallet']['litecoin']['network'])
    print("\tWIF:         ", JOut['wallet']['litecoin']['WIF'])
    print("\tAddress:     ", JOut['wallet']['litecoin']['address'], " (P2PKH)")
    if not Args.testnet:
        print("\tBech32 Addr: ", JOut['wallet']['litecoin']['bech32'])


####################################################################################################
##
## MAIN AND ARGS PROCESSING FUNCTIONS
##


def main():    
    global dataDict
    global Args
    global JOut

    outDir = Args.outDir
    template = Args.template

    ## Get all data into JOut json object
    jsonExportPrivate()
    if set(Args.blockchain) & set(["all","Bitcoin", "btc", "xbt"]):
        jsonExportBitcoinWallet()
    if set(Args.blockchain) & set(["all","Ethereum", "eth"]):
        jsonExportEthereumWallet()
    if set(Args.blockchain) & set(["all","EthereumClassic", "etc"]):
        jsonExportEthereumClassicWallet()
    if set(Args.blockchain) & set(["all","Quadrans", "qdc"]):
        jsonExportQuadransWallet()
    if set(Args.blockchain) & set(["all","Dash", "dash"]):
        jsonExportDashWallet()
    if set(Args.blockchain) & set(["all","Litecoin", "ltc"]):
        jsonExportLiteCoinWallet()

    ## Output in choosen type(s)
    if set(Args.output) & set(["txt", "text", "t"]):
        printSeed()
        if set(Args.blockchain) & set(["all","Bitcoin", "btc", "xbt"]):
            printBitcoinWallet()
        if set(Args.blockchain) & set(["all","Ethereum", "eth"]):
            printEthereumWallet()
        if set(Args.blockchain) & set(["all","EthereumClassic", "etc"]):
            printEthereumClassicWallet()
        if set(Args.blockchain) & set(["all","Quadrans", "qdc"]):
            printQuadransWallet()
        if set(Args.blockchain) & set(["all","Dash", "dash"]):
            printDashWallet()
        if set(Args.blockchain) & set(["all","Litecoin", "ltc"]):
            printLiteCoinWallet()

    if set(Args.output) & set(["json","j"]):
        print (json.dumps(JOut,indent=4))

    if set(Args.output) & set(["pdf","p"]):
        for coin in JOut['wallet'].keys():
            pdfw.pdfPaperWallet(JOut, coin, outDir, template, Args.format)

    if set(Args.output) & set(["qrcode","qr", "q"]):
        pass
    



def parseArguments():
    global Args
    """ parsing arguments """
    parser = argparse.ArgumentParser("Vanilla Wallet command line arguments")
    parser.add_argument("-bc", "--blockchain", help="Optional, the blockchain(s) the wallet is generater for. Default: all", 
        type=str, required=False, default="all", nargs='*',
        choices=[
            "all",
            "Bitcoin", "btc", "xbt", 
            "Litecoin", "ltc",
            "Ethereum", "eth",
            "EthereumClassic", "etc",
            "Quadrans", "qdc",
            "Dash", "dash"
            ])

    ## Input and data
    parser.add_argument("-e", "--entropy", help="An optional random string in case you prefer providing your own entropy", type=str, required=False)
    parser.add_argument("-l", "--language", help="Optional, the language for the mnemonic words list (BIP39). Default: english", type=str, required=False, default="english", choices=["english", "chinese_simplified", "chinese_traditional", "french", "italian", "japanese", "korean", "spanish"])
    parser.add_argument("-t", "--testnet", help="Generate addresses for test net (default is main net)", dest='testnet', action='store_const', const=True, default=False)
    parser.add_argument("-r", "--restore", help="Restore a wallet from BIP39 word list", dest="restore", type=str, required=False)
    parser.add_argument("-p", "--password", help="Password for wallet encryption", dest="password", type=str, required=False)
    
    ## Output and format
    parser.add_argument("-n", "--number", help="Optional, print BIP39 word list in numbered table", dest='wordlist', action='store_const', const=True, default=False)
    parser.add_argument("-o", "--output", help="Type of desired output(s), can be specify multiple(json, pdf or qrcodes)", type=str, dest="output", nargs='*', required=False, default="txt", choices=['text', 'txt', 't', 'json', 'j', 'pdf', 'p', 'qrcode', 'qr', 'q'])
    parser.add_argument("-d", "--directory", help="An optional where to save produced files (json, pdf or qrcodes)", type=str, required=False, default=".", dest="outDir")
    parser.add_argument("-T", "--template", help="Use alternative SVG template for paper wallet", dest="template", type=str, required=False, default="vanilla_template.svg")
    parser.add_argument("-f", "--format", help="Use A4 or Letter template for paper wallet", dest="format", type=str, required=False, default="a4", choices=['a4', 'letter'])

    Args = parser.parse_args()

    ## Additional arguments tests
    if not os.path.isdir(Args.outDir):
        print("Designated destination folder '%s' does not exist!" % Args.outDir)
        exit()

    if not os.path.isfile(Args.template):
        print("Chosen template file '%s' does not exist!" % Args.template)
        exit()
    
    if set(Args.output) & set(["pdf","p"]):
        executables = ['/usr/bin/google-chrome','/usr/bin/chromium','/usr/bin/brave-browser']
        found = False
        for ex in executables:
            if os.path.isfile(ex) and os.access(ex, os.X_OK):
                found = True
                break
        if not found:
            print("PDF paper wallet output requires Google Chrome or Brave Browser but you have none!")
            exit()

####################################################################################################
###
###    START
###


if sys.version_info[0] < 3:
    raise Exception("Python 3 or a more recent version is required.")

if __name__ == "__main__": 
    # What does the user want?
    parseArguments()

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

