####################################################################################################
##
## PDF PAPER WALLET PRINTING FUNCTIONS
##

import io
import segno
import base64
from svglib.svglib import svg2rlg
from reportlab.graphics import renderPDF
import sys, os, subprocess

def svg2pdf(infile, outfile):
    ### SVG to PDF with Chrome
    bashCommand = "brave-browser --headless --disable-gpu --landscape=1 --print-to-pdf="+outfile+" "+infile
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output = process.wait()
    if (output != 0 ): 
        return False

def qr64(info):
    buff = io.BytesIO()
    segno.make(info, micro=False).save(buff, kind='png', scale=4)
    buffStr=buff.getvalue()
    buff.close()
    result = ''+base64.b64encode(buffStr).decode()
    buffStr=None
    return result

def pdfBitcoinWallet(JOut):
    # global JOut

    address=JOut['wallet']['bitcoin']['address']
    words=JOut['keys']['bip39words'].split(" ")
    segwitAddress=JOut['wallet']['bitcoin']['segwitAddress']
    bech32=JOut['wallet']['bitcoin']['bech32']
    privateKey=JOut['keys']['privateKey']

    mnemonic1=', '.join(words[0:12])
    mnemonic2=', '.join(words[12:24])
    wif=JOut['wallet']['bitcoin']['WIF']
    wt=''

    with open('gfx/T3.svg','r') as file:
        wt = file.read()

    ## Make all qrcodes as base64 string
    address_qr = qr64(address)
    segwit_qr = qr64(segwitAddress)
    bech32_qr = qr64(bech32)
    private_qr = qr64(privateKey)

    ## Replace SVG Placehoders with actual values
    for idx, word in enumerate(JOut['keys']['bip39words'].split(" ")):
        wordPH='__{}__'.format(idx+1)
        wt=wt.replace(wordPH,word)

    wt=wt.replace('__legacy-qr__', 'data:image/png;base64,'+address_qr)\
    .replace('__segwit-qr__', 'data:image/png;base64,'+segwit_qr)\
    .replace('__bech32-qr__', 'data:image/png;base64,'+bech32_qr)\
    .replace('__private-qr__', 'data:image/png;base64,'+private_qr)\
    .replace('__legacy__', address)\
    .replace('__wif__', wif)\
    .replace('__segwit__',segwitAddress)\
    .replace('__bech32__',bech32)\
    .replace('__private__',privateKey)


    ## Rotate SVG

    ## Save SVG
    with open(address+".svg", "w") as f :
        f.write(wt)
    
    ## svg to PDF ??
