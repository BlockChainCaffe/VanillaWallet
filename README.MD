# Vanilla Wallet

<img src="logo.png" width="150" align="right" vspace="15" hspace="15">

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
In order to create paper wallets just use the ```-o pdf``` flag on the command line.
The paper wallet is provided in PDF format for your convenience. It is generated starting from a SVG template where graphic elements (coin logo and
qrcodes) are set with a simple 'find&replace' approach. 
You can design your template and use it instead of the default provided one.
In order to get the PDF, the conversion from SVG to PDF is done using Google Chrome or Chromium or Brave browser since this is providing better results
at the time for colors and transparency. 

## How to use it

[![IMAGE ALT TEXT](http://img.youtube.com/vi/AjrZ0ga8VjA/0.jpg)](http://www.youtube.com/watch?v=AjrZ0ga8VjA "Video Title")

The sujested procedure is:
  * download a linux distro and make a live USB key
  * boot your PC from the live USB key
  * download the source code via git or zip 
  * run the install.sh to install the dependecies via apt-get and pip3
  ```sh
  $ bash install-sh
  ```
  * DISCONNECT THE PC FROM INTERNET, turn off wifi etc
  * generate the wallets (see examples below)
  * save the generated wallets in a secure way
  * **do not** print the PDF wallets on a printer (might save copies on a local HD)


## Installation
For Debian, Ubuntu, Mint and similar just run

```
$ bash install
```

Otherwise issue the following commands or equivalent, depending on your distro. Ensure you have python3 and other installed 


```
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

Here a list of the options you can use:

- **-h --help**  : get the help/usage mesage
- **-t --testnet**  : make a testnet wallet
- **-bc \<coin\> --blockchain \<coin\>**  : specify one or more coins, makes a wallet for each. Possible values are:
    - all (default)
    - Bitcoin/btc/xbt
    - Litecoin/ltc
    - Ethereum/eth
    - EthereumClassic/etc
    - Quadrans/qdc
    - Dash/dash
- **-e \<ENTROPY\>  --entropy \<ENTROPY\>**  : A random string in case you prefer providing your own entropy
- **-l  --language**  : Optional, the language for the mnemonic words list (**not BIP39**).
    - english (default)
    - chinese_simplified
    - chinese_traditional
    - french
    - italian
    - japanese
    - korean
    - spanish
- **-r \<WORDLIST\>, --restore \<WORDLIST\>**  : Restore a wallet from word list (**not BIP39**)
- **-p \<PASSWORD\>, --password \<PASSWORD\>**  : Password for wallet encryption
- **-n, --number** : Optional, print word list in numbered table in text mode output
- **-o \<FORMAT\> --output \<FORMAT\>**  : Type of desired output format, can be specify more than one
    - text/txt/t (default)
    - json/j
    - pdf/p
    - qrcode/qr/q
- **-d \<OUTDIR\> --directory \<OUTDIR\>**  : An optional where to save produced files
- **-T \<TEMPLATE\>, --template \<TEMPLATE\>**  : optional personalized svg template  
- **-f \<PAPERFORMAT\> --format \<PAPERFORMAT\>**: output paper sheet format
    - a4 (default)
    - letter

```sh
$ ./vanilla.py [-h] 
$ ./vanilla.py [options [options]]
```

## Examples

Create a testnet address for bitcoin using supplied entropy and get plain text output
```sh
python3 vanillay.py -e 3nTroPy -t -n -bc btc 
```

Create a real bitcoin paper wallet in letter format using noise generated entropy and spanish recovery words
```sh
python3 vanillay.py -l spanish -bc btc -o pdf -f letter
```

Create a Dash wallet in json format
```sh
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

  - 🧡 Bitcoin : 1B9KmAzuFoLtjipL97pD2pBAszSuqREf8X
  - 💙 Dash : XyLXs5Reta5PRZNczM19ThJvkZ53RHi7XD
