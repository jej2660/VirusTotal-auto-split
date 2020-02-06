import requests
import sys
import json
import os
import time

url_r = 'https://www.virustotal.com/vtapi/v2/file/report'
url_s = 'http://www.virustotal.com/vtapi/v2/file/scan'
api_key = ''#your api key
resource = ""
params_r = {'apikey': api_key, 'resource': resource}
params = {'apikey': api_key}
path = "./pool/"
judge = 20 #How many engine detect a file is malware
clock = 0
resource_arr = []
processing = 0

def FileScan(filepath, api_key):
    files = {'file': (open(path+filepath, 'rb'))}
    response = requests.post(url_s, files = files, params = params)
    return response.json()

def GetReport(reso):
    rpar = {'apikey': api_key, 'resource': reso}
    while 1:
        response = requests.get(url_r, params=rpar)
        if response.status_code == 200:
            return response.json()
            break
        else:
            time.sleep(5)
    
dirls = os.listdir(path)

for fi in dirls:
    dr = FileScan(fi, api_key)
    resource_arr.append(dr["resource"])
    clock += 1
    processing += 1
    print(str(processing) + " send!.\n")
    if clock % 4 == 0:
        print("Queue delay\n")
        time.sleep(60)

print("File send complete!!\n")

for fr in resource_arr:
    print(fr)
    ds = GetReport(fr)
    if ds['positives'] > judge:
        pos = resource_arr.index(fr)
        file_pos = path + dirls[pos]
        os.system("mv " + file_pos + " ./mal/" + dirls[pos])
    else:
        pos = resource_arr.index(fr)
        file_pos = path + dirls[pos]
        os.system("mv " + file_pos + " ./normal/" + dirls[pos])
