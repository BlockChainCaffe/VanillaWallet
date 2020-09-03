# Vanilla Wallet

Vanilla Wallet is a cold storage wallet generato for multiple crypto currencies written in python. It generates a private key and then derives all the addresses for all coins from that same private key.
The private key is then converted to BIP39 recovery word list
The results can be used to generate paper wallets or other cold storage

## Supported coins

 - Bitcoin (legacy, segwith, bech32)
 - Dash
 - Litecoin 
 - Ethereum (Ethereum, EthereumClassic, Quadrans...)
 - Monero (coming soon)

## Key Geneation
Vanilla can generate the private key from a string supplied by the user or from noise capured from the microphone. Those are used as inital entropy, then are hashed multiple times in a raw with optional salt

## Installation
Ensure you have python3 installed, then install the dependecies with:
`pip3 install -r requirements.txt`

## Usage
`> python3 vanilla.py -h
usage: Vanilla Wallet command line arguments [-h] [-e ENTROPY]
                                             [-l {english,chinese_simplified,chinese_traditional,french,italian,japanese,korean,spanish}]
                                             [-t] [-r RESTORE]

optional arguments:
  -h, --help            show this help message and exit
  -e ENTROPY, --entropy ENTROPY
                        An optional random string in case you prefer providing
                        your own entropy
  -l {english,chinese_simplified,chinese_traditional,french,italian,japanese,korean,spanish}, --language {english,chinese_simplified,chinese_traditional,french,italian,japanese,korean,spanish}
                        Optional, the language for the mnemonic words list
                        (BIP39). Default: english
  -t, --testnet         Generate addresses for test net (default is main net)
  -r RESTORE, --restore RESTORE
                        Restore a wallet from BIP39 word list`

 ## Disclaimer
*This code is provided  ​“AS IS” with all faults, defects, bugs, and errors. Developers, authors  and mantainers of the code makes no warranties, express or implied, and hereby disclaims all implied warranties, including any warranty of merchantability and warranty of fitness for a particular purpose. 
Use it at your own risk. Developers, authors  and mantainers cannot be held responsible for any damage or loss deriving from the use of this code*

## Contributors and Credits
- Massimo S. Musumeci massmux https://github.com/massmux/bip39gen
- MaxP