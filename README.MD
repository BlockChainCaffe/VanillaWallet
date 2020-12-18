# Vanilla Wallet

<img src="gfx/logo.png" width="100" align="right" vspace="15" hspace="15">

Vanilla Wallet is a cold storage wallet generator for multiple crypto currencies written in python. 
It generates a private key and then derives all the addresses for all coins from that same private key.
The private key is then converted to BIP39 recovery word list (not compatible with other wallets as of today)
It can output the result in text (default), json and pdf (paper wallets)

## Supported coin families
 - Bitcoin (legacy, segwith, bech32)
 - Dash
 - Litecoin 
 - Ethereum based (Ethereum, EthereumClassic, Quadrans...)
 - (More to come, requests an contribuitons welcome)

## Key Geneation
Vanilla can generate the private key from a string supplied by the user or from noise capured from the microphone/audio device. Those are used as inital entropy, then are hashed multiple times with an optional salt

## Paper Wallets & Templates
In order to create paper wallets just use the '-o pdf' flag on the command line.
The paper wallet is provided in PDF format for your convenience. It is generated starting from a SVG template where graphic elements (coin logo and
qrcodes) are set with a simple 'find&replace' approach. 
You can design your template and use it instead of the default provided one.
In order to get the PDF, the conversion from SVG to PDF is done using Google Chrome or Chromium or Brave browser since this is providing better results
at the time for colors and transparency. 

## How to use it
The sujested procedure is:
  * download a linux distro and make a bootable USB key
  * boot your PC from the USB key
  * download the source code via git
  * install the dependecies via apt-get and pip3
  * DISCONNECT THE PC FROM INTERNET, turn off wifi etc
  * generate the wallets
  * save the generate wallets in a secure way
  * do not print the PDF wallets on a printer that might record copies on a local HD


## Installation
This is the procedure for Debian, Ubuntu and Mint. 
```
Ensure you have python3 installed, then install the dependecies with:
sudo apt-get udate
sudo apt-get upgrade
sudo apt-get install git
sudo apt-get install python3-pyaudio
sudo apt-get install python3-pyaudio
sudo apt-get install chromium-browser
pip3 install -r requirements.txt
```



## Options
Using the command line options below you can choose to:
  * to provide a string for entropy or
  * to use the microphone/sound card to gather noise
  * to restore a previously generate vanilla address
  * to have the output human-readable form and/or json and/or pdf paper wallet
  * the language used for BIP39 (check you have the right locales installed)
  * have the results for one specific blockchain or all those supported


## Usage
```
> ./vanilla.py -h
usage: Vanilla Wallet command line arguments [-h]
                                             [-bc [{all,Bitcoin,btc,xbt,Litecoin,ltc,Ethereum,eth,EthereumClassic,etc,Quadrans,qdc,Dash,dash} [{all,Bitcoin,btc,xbt,Litecoin,ltc,Ethereum,eth,EthereumClassic,etc,Quadrans,qdc,Dash,dash} ...]]]
                                             [-e ENTROPY] [-l {english,chinese_simplified,chinese_traditional,french,italian,japanese,korean,spanish}] [-t] [-r RESTORE] [-p PASSWORD] [-n]
                                             [-o [{text,txt,t,json,j,pdf,p,qrcode,qr,q} [{text,txt,t,json,j,pdf,p,qrcode,qr,q} ...]]] [-d OUTDIR] [-T TEMPLATE]

optional arguments:
  -h, --help            show this help message and exit
  -bc [{all,Bitcoin,btc,xbt,Litecoin,ltc,Ethereum,eth,EthereumClassic,etc,Quadrans,qdc,Dash,dash} [{all,Bitcoin,btc,xbt,Litecoin,ltc,Ethereum,eth,EthereumClassic,etc,Quadrans,qdc,Dash,dash} ...]], --blockchain [{all,Bitcoin,btc,xbt,Litecoin,ltc,Ethereum,eth,EthereumClassic,etc,Quadrans,qdc,Dash,dash} [{all,Bitcoin,btc,xbt,Litecoin,ltc,Ethereum,eth,EthereumClassic,etc,Quadrans,qdc,Dash,dash} ...]]
                        Optional, the blockchain(s) the wallet is generater for. Default: all
  -e ENTROPY, --entropy ENTROPY
                        An optional random string in case you prefer providing your own entropy
  -l {english,chinese_simplified,chinese_traditional,french,italian,japanese,korean,spanish}, --language {english,chinese_simplified,chinese_traditional,french,italian,japanese,korean,spanish}
                        Optional, the language for the mnemonic words list (BIP39). Default: english
  -t, --testnet         Generate addresses for test net (default is main net)
  -r RESTORE, --restore RESTORE
                        Restore a wallet from BIP39 word list
  -p PASSWORD, --password PASSWORD
                        Password for wallet encryption
  -n, --number          Optional, print BIP39 word list in numbered table
  -o [{text,txt,t,json,j,pdf,p,qrcode,qr,q} [{text,txt,t,json,j,pdf,p,qrcode,qr,q} ...]], --output [{text,txt,t,json,j,pdf,p,qrcode,qr,q} [{text,txt,t,json,j,pdf,p,qrcode,qr,q} ...]]
                        Type of desired output(s), can be specify multiple(json, pdf or qrcodes)
  -d OUTDIR, --directory OUTDIR
                        An optional where to save produced files (json, pdf or qrcodes)
  -T TEMPLATE, --template TEMPLATE
                        Use alternative SVG template for paper wallet
  -f {a4,letter}, --format {a4,letter}
                        Use A4 or Letter template for paper wallet
```

## Examples

Create a testnet address for bitcoin using supplied entropy and get plain text output
```
python3 vanillay.py -e 3nTroPy -t -n -bc btc 
```

Create a real bitcoin paper wallet in letter format using noise generated entropy and spanish recovery words
```
python3 vanillay.py -l spanish -bc btc -o pdf -f letter
```

Create a Dash wallet in json format
```
python3 vanillay.py -bc dash -o json
```


## Disclaimer
*This code is provided  ​“AS IS” with all faults, defects, bugs, and errors. Developers, authors  and mantainers of the code makes no warranties, express or implied, and hereby disclaims all implied warranties, including any warranty of merchantability and warranty of fitness for a particular purpose. 
Use it at your own risk. Developers, authors  and mantainers cannot be held responsible for any damage or loss deriving from the use of this code*

## Contributors and Credits
- Massimo S. Musumeci massmux https://github.com/massmux/bip39gen
- MaxP
- Franco

## Donations
Support the project by showinf your love and make a donation:
🧡 Bitcoin : 1B9KmAzuFoLtjipL97pD2pBAszSuqREf8X
💙 Dash : XyLXs5Reta5PRZNczM19ThJvkZ53RHi7XD
