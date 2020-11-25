####################################################################################################
##
## PDF PAPER WALLET PRINTING FUNCTIONS
##

def printBitcoinPaperWallet():

    address=JOut['wallet']['bitcoin']['address']
    words=JOut['keys']['bip39words'].split(" ")
    segwitAddress=JOut['wallet']['bitcoin']['segwitAddress']
    bech32=JOut['wallet']['bitcoin']['bech32']
    privateKey=JOut['keys']['privateKey']

    mnemonic1=', '.join(words[0:12])
    mnemonic2=', '.join(words[12:24])
    wif=JOut['wallet']['bitcoin']['WIF']
    wt=''

    with open('Template_puro.svg','r') as file:
        wt = file.read()

    buff = io.BytesIO()
    segno.make(address, micro=False).save(buff, kind='png', scale=4)
    buffStr=buff.getvalue()
    buff.close()

    address_qr = ''+base64.b64encode(buffStr).decode()
    buffStr=None

    buff = io.BytesIO()
    segno.make(segwitAddress, micro=False).save(buff, kind='png', scale=4)
    buffStr=buff.getvalue()
    buff.close()
    segwit_qr=base64.b64encode(buffStr).decode()

    buffStr=None

    buff = io.BytesIO()
    segno.make(bech32, micro=False).save(buff, kind='png', scale=4)
    buffStr=buff.getvalue()
    buff.close()
    bech32_qr=base64.b64encode(buffStr).decode()


    for idx, word in enumerate(JOut['keys']['bip39words'].split(" ")):
        wordPH='__{}__'.format(idx+1)
        wt=wt.replace(wordPH,word)


##    print(address)
##    print(segwitAddress)
##    print(bech32)
    wt=wt.replace('__legacy-qr__', 'data:image/png;base64,'+address_qr)\
    .replace('__segwit-qr__', 'data:image/png;base64,'+segwit_qr)\
    .replace('__bech32-qr__', 'data:image/png;base64,'+bech32_qr)\
    .replace('__legacy__', address)\
    .replace('__wif__', wif)\
    .replace('__segwit__',segwitAddress)\
    .replace('__bech32__',bech32)\
    .replace('__private__',privateKey)

    bio = io.BytesIO(io.StringIO(wt).read().encode('utf8'))
    drawing = svg2rlg(bio)
    bio.close()
    renderPDF.drawToFile(drawing, address+".pdf")
    f = open(address+".svg", "w")
    f.write(wt)
    f.close()
