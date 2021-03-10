transmited_data = ""
file = open('Untitled.csv')
data = file.readlines()

for i in range(0,len(data)):
	try:
		data_chr = data[i].split(",")[3].replace("\"","")
	except:
		data_chr = ""
	transmited_data += data_chr

print transmited_data


'''
Output:
.
.
.
[LOG] Connection from ab290d3a380f04c2f0db98f42d5b7adea2bd0723fa38e0621fb3d7c1c2808284
[LOG] Connection from a7e6ec5bb39a554e97143d19d3bfa28a9bbef68fa6ecab3b3ef33919547278d4
[LOG] Connection from 099319f700d8d5f287387c81e6f20384c368a9de27f992f71c1de363c597afd4
[LOG] Connection from ab290d3a380f04c2f0db98f42d5b7adea2bd0723fa38e0621fb3d7c1c2808284
[LOG] Connection from HTB{45ynch20n0u5_ch4nn315_c4n_41w4y5_5w4p_f23qu3ncy}
[LOG] Connection from HTB{45ynch20n0u5_ch4nn315_c4n_41w4y5_5w4p_f23qu3ncy}
'''