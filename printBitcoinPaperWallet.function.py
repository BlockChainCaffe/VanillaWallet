def printBitcoinPaperWallet():
    global JOut

    address=JOut['wallet']['bitcoin']['address']
    words=JOut['keys']['bip39words'].split(" ")
    mnemonic1=', '.join(words[0:12])
    mnemonic2=', '.join(words[12:24])
    wif=JOut['wallet']['bitcoin']['WIF']
    wt=''

    with open('bitcoin_wallet.svg','r') as file:
        wt = file.read()

    buff = io.BytesIO()
    segno.make(address, micro=False).save(buff, kind='png', scale=4)
    buffStr=buff.getvalue()
    buff.close()

    address_qr = ''+base64.b64encode(buffStr).decode()


    buff = io.BytesIO()
    segno.make(wif, micro=False).save(buff, kind='png', scale=4)
    buffStr=buff.getvalue()
    buff.close()
    secret_key_qr=base64.b64encode(buffStr).decode()
    
    wt=wt.replace('__address_qr__', 'data:image/png;base64,'+address_qr)\
    .replace('__secret_key_qr__', 'data:image/png;base64,'+secret_key_qr)\
    .replace('__address__', address)\
    .replace('__secret_key__', wif)\
    .replace('__language__',Args.language)\
    .replace('__mnemonic_row1__',mnemonic1)\
    .replace('__mnemonic_row2__',mnemonic2)

    bio = io.BytesIO(io.StringIO(wt).read().encode('utf8'))
    drawing = svg2rlg(bio)
    bio.close()
    renderPDF.drawToFile(drawing, address+".pdf")
    # cairosvg.svg2pdf( bytestring=wt.encode('utf-8'), write_to="VW_"+address+".pdf")
    f = open(address+".svg", "w")
    f.write(wt)
    f.close()
