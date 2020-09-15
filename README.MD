# Vanilla Wallet

<img src="gfx/logo.png" width="100" align="right" vspace="15" hspace="15">

Vanilla Wallet is a cold storage wallet generator for multiple crypto currencies written in python. It generates a private key and then derives all the addresses for all coins from that same private key.
The private key is then converted to BIP39 recovery word list
The results can be used to generate paper wallets or other cold storage

## Supported coins
 - Bitcoin (legacy, segwith, bech32)
 - Dash
 - Litecoin 
 - Ethereum based (Ethereum, EthereumClassic, Quadrans...)
 - (More to come)

## Key Geneation
Vanilla can generate the private key from a string supplied by the user or from noise capured from the microphone/audio device. Those are used as inital entropy, then are hashed multiple times in a row with an optional salt

## Options
Using the command line options below you can choose to:
  * to provide a string for entropy or
  * to use the microphone/sound card to gather noise
  * to restore a previously generate vanilla address
  * to have the output human-readable form or json
  * the language used for BIP39 (check you have the right locales installed)
  * have the results for one specific blockchain or all those supported


## Installation
Ensure you have python3 installed, then install the dependecies with:
`pip3 install -r requirements.txt`

## Usage
```
> ./vanilla.py -h
usage: Vanilla Wallet command line arguments 
      [-h] [-bc {all,Bitcoin,btc,xbt,Litecoin,ltc,Ethereum,eth,EthereumClassic,etc,Quadrans,qdc,Dash,dash}]
      [-wn] [-e ENTROPY]
      [-l {english,chinese_simplified,chinese_traditional,french,italian,japanese,korean,spanish}]
      [-t] [-r RESTORE] [-p PASSWORD]
      [-j] [-d DIRECTORY] [-q]

optional arguments:
  -h, --help            show this help message and exit
  -bc {all,Bitcoin,btc,xbt,Litecoin,ltc,Ethereum,eth,EthereumClassic,etc,Quadrans,qdc,Dash,dash}, --blockchain {all,Bitcoin,btc,xbt,Litecoin,ltc,Ethereum,eth,EthereumClassic,etc,Quadrans,qdc,Dash,dash}
                        Optional, the blockchain the wallet is generater for.
                        Default: all
  -wn, --wordnumber     Optional, print BIP39 word list in numbered table
  -e ENTROPY, --entropy ENTROPY
                        An optional random string in case you prefer providing
                        your own entropy
  -l {english,chinese_simplified,chinese_traditional,french,italian,japanese,korean,spanish}, --language {english,chinese_simplified,chinese_traditional,french,italian,japanese,korean,spanish}
                        Optional, the language for the mnemonic words list
                        (BIP39). Default: english
  -t, --testnet         Generate addresses for test net (default is main net)
  -r RESTORE, --restore RESTORE
                        Restore a wallet from BIP39 word list
  -p PASSWORD, --password PASSWORD
                        Password for wallet encryption
  -j, --json            Produce only json output
  -d DIRECTORY, --directory DIRECTORY
                        An optional where to save produced files (json and qr
                        codes)
  -q, --qrcode          Generate qrcodes for addresses and keys
  ```

 ## Disclaimer
*This code is provided  ​“AS IS” with all faults, defects, bugs, and errors. Developers, authors  and mantainers of the code makes no warranties, express or implied, and hereby disclaims all implied warranties, including any warranty of merchantability and warranty of fitness for a particular purpose. 
Use it at your own risk. Developers, authors  and mantainers cannot be held responsible for any damage or loss deriving from the use of this code*

## Contributors and Credits
- Massimo S. Musumeci massmux https://github.com/massmux/bip39gen
- MaxP