printable = ""
file = open('exported_data.csv')
data = file.readlines()

for i in range(0,len(data)):
	try:
		data_chr = data[i].split(",")[1].replace("\"","")
	except:
		data_chr = ""
	if data_chr.isprintable() and len(data_chr) == 1 and ord(data_chr)<250:
		printable += data_chr


flag_index = printable.find("HTB{")
print(printable[flag_index:flag_index+100])


'''
Output:
HTB{microSD_cards_usually_use_SPI_for_serial_interfacing}·ð.ã........E.B..?Y'5..)wu.P.0.D.D.Äôr.E.@.
'''