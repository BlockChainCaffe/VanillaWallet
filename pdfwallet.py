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

import svglogos

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

def pdfPaperWallet(JOut, coin):
    # global JOut

    ## Do we have an address?? (special case for Dash)
    if 'address' in JOut['wallet'][coin].keys():
        address=JOut['wallet'][coin]['address']
    elif 'addrP2PKH' in JOut['wallet'][coin].keys():
        address=JOut['wallet'][coin]['addrP2PKH']

    words=JOut['keys']['bip39words'].split(" ")
    mnemonic1=', '.join(words[0:12])
    mnemonic2=', '.join(words[12:24])
    privateKey=JOut['keys']['privateKey']

    wt=''
    with open('gfx/T5.svg','r') as file:
        wt = file.read()

    ## Replace the coin name and logo
    wt=wt.replace('__coin_svg_logo__', svglogos.coin_svg[coin]['gliph'] )\
        .replace('__transform__', svglogos.coin_svg[coin]['transform'] )\
        .replace('__coin_name__', coin.capitalize() )

    ## Replace basic values (those can't be missing!!)
    address_qr = qr64(address)
    private_qr = qr64(privateKey)
    wt=wt.replace('__legacy-qr__', 'data:image/png;base64,'+address_qr)\
        .replace('__private-qr__', 'data:image/png;base64,'+private_qr)\
        .replace('__legacy__', address)\
        .replace('__private__',privateKey)        
    
    ## Replace SVG Placehoders with actual values
    for idx, word in enumerate(JOut['keys']['bip39words'].split(" ")):
        wordPH='__{}__'.format(idx+1)
        wt=wt.replace(wordPH,word)

    
    ## Do we have Segwit?
    if 'segwitAddress' in JOut['wallet'][coin].keys():
        segwitAddress= JOut['wallet'][coin]['segwitAddress']
        segwit_qr = qr64(segwitAddress)
        wt = wt.replace('__segwit__',segwitAddress)
        wt = wt.replace('__segwit-qr__', 'data:image/png;base64,'+segwit_qr)
    elif 'addrP2SH' in JOut['wallet'][coin].keys():
        p2sh = JOut['wallet'][coin]['addrP2SH']
        p2sh_qr = qr64(p2sh)
        wt = wt.replace('__segwit__',p2sh)
        wt = wt.replace('__segwit-qr__', 'data:image/png;base64,'+p2sh_qr)
        wt = wt.replace('SegWit','P2SH')
    else:
        wt = wt.replace('SegWit: __segwit__','')\
            .replace('SegWit','')

    ## Do we have bech32?
    if 'bech32' in JOut['wallet'][coin].keys() :
        bech32= JOut['wallet'][coin]['bech32']
        bech32_qr = qr64(bech32)
        wt = wt.replace('__bech32__',bech32)
        wt = wt.replace('__bech32-qr__', 'data:image/png;base64,'+bech32_qr)
    else:
        wt = wt.replace('Bech 32: __bech32__','')\
            .replace('Bech32','')

    ## Do we have WIF?
    if 'WIF' in JOut['wallet'][coin].keys():
        wif=JOut['wallet'][coin]['WIF']
        wt = wt.replace('__wif__', wif)
    else:
        wt = wt.replace('__wif__','')\
            .replace('WIF :','')





    ## Rotate SVG

    ## Save SVG
    with open(address+".svg", "w") as f :
        f.write(wt)
    
    ## svg to PDF ??
