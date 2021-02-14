####################################################################################################
##
## PDF PAPER WALLET PRINTING FUNCTIONS
##

import io
import segno
import base64

# import PyPDF2

import sys, os, subprocess
import svglogos

def svg2html(infile, outfile, format):
    ## Open Template
    ht=''
    format_file=''
    if format=='letter':
        format_file='letter_landscape.html'
    else:
        format_file='a4_landscape.html'

    with open(format_file,'r') as file:
        ht = file.read()

    ## Replace the coin name and logo (those can't be missing!!)
    ht=ht.replace('__SVG__',infile)

    ## Save SVG
    with open(outfile, "w") as f :
        f.write(ht)


def html2pdf(infile, outfile):
    ### HTML to PDF with Brave (or Chrome)
    # 
    # I know there are modules to do this in pure python
    # They just suck at handling complex html with transparencies, overlapping etc
    # I found that Brave (or Chrome) headless browser does a far better job even
    # if it missess some features
    #
    # https://support.brave.com/hc/en-us/articles/360044860011-How-Do-I-Use-Command-Line-Flags-in-Brave-
    # https://chromedevtools.github.io/devtools-protocol/tot/Page/#method-printToPDF

    ## Need one of those two executable. Pick one
    if os.path.isfile('/usr/bin/google-chrome'):
        bashCommand = "/usr/bin/google-chrome --headless --no-sandbox --disable-gpu --print-to-pdf="+outfile+" "+infile
    elif os.path.isfile('/usr/bin/chromium'):
        bashCommand = "/usr/bin/chromium --headless --no-sandbox --disable-gpu --print-to-pdf="+outfile+" "+infile
    else:
        bashCommand = "/usr/bin/brave-browser --headless --no-sandbox --disable-gpu --print-to-pdf="+outfile+" "+infile

    # Open a "silenced" (stdout & stderr >> /dev/null) subprocess
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    output = process.wait()
    if (output != 0 ): 
        return False

# def rotatePDF(input, output):
#     pdfIn = open(input, 'rb')
#     pdfReader = PyPDF2.PdfFileReader(pdfIn)
#     pdfWriter = PyPDF2.PdfFileWriter()

#     for pageNum in range(pdfReader.numPages):
#         page = pdfReader.getPage(pageNum)
#         page.rotateClockwise(90)
#         pdfWriter.addPage(page)

#     pdfOut = open(output, 'wb')
#     pdfWriter.write(pdfOut)
#     pdfOut.close()
#     pdfIn.close()

def qr64(info):
    buff = io.BytesIO()
    segno.make(info, micro=False).save(buff, kind='png', scale=4)
    buffStr=buff.getvalue()
    buff.close()
    result = ''+base64.b64encode(buffStr).decode()
    buffStr=None
    return result


####################################################################################################
##
## PDF PAPER TEMPLATE FILLING
##

def pdfPaperWallet(JOut, coin, outDir, template, format):

    ## Open Template
    wt=''
    with open(template,'r') as file:
        wt = file.read()

    ## Replace the coin name and logo (those can't be missing!!)
    wt=wt.replace('__coin_svg_logo__', svglogos.coin_svg[coin]['gliph'] )\
        .replace('__transform__', svglogos.coin_svg[coin]['transform'] )\
        .replace('__coin_name__', coin.capitalize() )
    
    ## Do we have an address?? (special case for Dash)
    if 'address' in JOut['wallet'][coin].keys():
        address=JOut['wallet'][coin]['address']
    elif 'addrP2PKH' in JOut['wallet'][coin].keys():
        address=JOut['wallet'][coin]['addrP2PKH']
    address_qr = qr64(address)
    wt=wt.replace('__legacy-qr__', 'data:image/png;base64,'+address_qr)
    
    ## Is it a BIP38 encrypted wallet?
    if 'BIP38' in JOut['wallet'][coin].keys():
        privateKey=JOut['wallet'][coin]['BIP38']
        wt=wt.replace('__private__',privateKey+"(bip38)")
    else:
        privateKey=JOut['keys']['privateKey']
        wt=wt.replace('__private__',privateKey)
    

    ## Do we have WIF?
    if 'WIF' in JOut['wallet'][coin].keys():
        wif=JOut['wallet'][coin]['WIF']
        wt = wt.replace('__wif__', wif)
        wif_qr = qr64(wif)
        wt=wt.replace('__private-qr__', 'data:image/png;base64,'+wif_qr)
    else:
        private_qr = qr64(privateKey)
        wt=wt.replace('__private-qr__', 'data:image/png;base64,'+private_qr)
        wt = wt.replace('__wif__','').replace('WIF :','')


    ## Replace basic values (those can't be missing!!)
    wt=wt.replace('__legacy__', address)\
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

    ## Save SVG
    with open(outDir+'/'+address+".svg", "w") as f :
        f.write(wt)

    ## svg to html
    svg2html(outDir+'/'+address+".svg", outDir+'/'+address+".html", format)
    ## html to PDF
    html2pdf(outDir+'/'+address+".html", outDir+'/'+address+".pdf")
    ## clean
    os.remove(outDir+'/'+address+".svg")
    os.remove(outDir+'/'+address+".html")

