import os
from tkinter import Y
import requests
import getpass
import json
import ipaddress
import signal
import sys
from colorama import Fore
from colorama import Style
from colorama import init
from time import sleep
from urllib3.exceptions import InsecureRequestWarning

#ERROR Handling ignore
def signal_handler(signal, frame):
    print("\n"+Fore.RED +" \U0000274C Control+C pressed, exiting application...\n")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

init()

articles = Fore.CYAN+Style.BRIGHT+" \U0001F4AB Support me by checking out my writeups at https://konecho.medium.com/ "+Style.RESET_ALL
summary = Fore.CYAN+Style.BRIGHT+" \U0001F4AB PullMyReports is a tool that allows you to automatically download reports from your Nessus Scanner using the Nessus API."+Style.RESET_ALL
sum2 = Fore.YELLOW+Style.BRIGHT+" \U0001F4CC NOTE: The application currently assumes 8834 to be the port being used by the Nessus appliance.\n"+Style.RESET_ALL
logo = Fore.CYAN+"""  
 _______         __  __  ___ ___         _______                             __          
|   _   |.--.--.|  ||  ||   Y   |.--.--.|   _   \.-----..-----..-----..----.|  |_ .-----.
|.  1   ||  |  ||  ||  ||.      ||  |  ||.  l   /|  -__||  _  ||  _  ||   _||   _||__ --|
|.  ____||_____||__||__||. \_/  ||___  ||.  _   1|_____||   __||_____||__|  |____||_____|
|:  |                   |:  |   ||_____||:  |   |       |__|                             
|::.|                   |::.|:. |       |::.|:. | """+Fore.YELLOW+"""\U0001F4DD NESSUS REPORT ASSISTANT V1.1"""+Fore.CYAN+"""                                      
`---'                   `--- ---'       `--- ---' """+Fore.MAGENTA+Style.BRIGHT+""">>> Made by KonEcho\U0001F431                                     
                                                """+Style.RESET_ALL
print(logo)
print(summary)
print(sum2)

#Disable any warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

#Exit function
while True:
    yesno = input(" \U0001F910 The application will now ask you for your Nessus portal credentials, Do you wish to continue?[y/n]  ")
    yesstrings = ["y", "yes", "Y", "Yes"]
    if yesno in yesstrings:
        print(Fore.GREEN+" \U00002705 Continuing...\n"+Style.RESET_ALL)
        break
    elif yesno not in yesstrings:
        print(Fore.RED+" \U0001F44B Sayonara! \n"+Style.RESET_ALL)
        exit()

#Enter the username and validate for actual input
def enter():
    while True:
        while True:
            enter.username = input(" \U0001F7E6 Please enter your Username: ")
            if not enter.username:
                print(Fore.RED+" \U0000274C Username cannot be blank!\n"+Style.RESET_ALL)
            else:
                break

        #Enter password and check for actual input too
        while True:
            enter.password = getpass.getpass(" >> Password for "+enter.username+": ")
            if not enter.password:
                print(Fore.RED+" \U0000274C Password cannot be blank!\n"+Style.RESET_ALL)
            else:
                break

        #enter and only accept IP Address loop
        enter.urlq = input(" \U0001F7E6 Please enter Nessus IP: ")
        while True:
            try:
                ipaddress.ip_address(enter.urlq)
            except ValueError:
                print(Fore.RED+" \U0000274C Invalid IP Address\n"+Style.RESET_ALL)
                enter.urlq = input(" \U0001F7E6 Please enter Nessus IP: ")
            else:
                break
        enter.url = "https://"+enter.urlq+":8834"

    #Create session token
    
        log = requests.post(enter.url+'/session', 
            data={
            'username': enter.username,
            'password': enter.password
                }, 
            verify=False)
        jsonResponse = log.json()
        

        if "token" in jsonResponse:
            print(Fore.GREEN+" \U00002705 Authentication successful...\n"+Style.RESET_ALL)
            enter.token = str("token="+jsonResponse['token'])
            break
        else:
            print(Fore.RED+" \U0000274C Authentication failed! Please re-enter your details...\n"+Style.RESET_ALL)
enter()

#Header in general to be used throughout the API's requests
head = {'content-type': 'application/json', 'Accept': 'application/json', 'X-Cookie': enter.token}

#Payload data for CSV's 
datapay = {

    "format": "csv",
        "reportContents": {
            "vulnerabilitySections": {
                "id": True,
                "cve": True,
                "cvss": True,
                "risk": True,
                "hostname": True,
                "protocol": True,
                "port": True,
                "plugin_name": False,
                "synopsis": False,
                "description": False,
                "solution": False,
                "see_also": False,
                "plugin_output": False,
                "stig_severity": False,
                "cvss3_base_score": False,
                "cvss_temporal_score": False,
                "cvss3_temporal_score": False,
                "risk_factor": False,
                "references": False,
                "plugin_information": False,
                "exploitable_with": True
            }
        }
}

#Retrieve list of folders and choose folder id
def start():
    while True:

        print(Fore.CYAN+" \U0001F4C1 Listing your folders...\n")
        listfolderurl = (enter.url+'/folders')
        listfolder = requests.get(url=listfolderurl, headers=head, verify=False)
        jsonFolder = listfolder.json()
        for data in jsonFolder['folders']:
            print (data['name']+' : '+str(data['id']))
        print("\n"+Style.RESET_ALL)

        #question for folder ID
        folderid=input(" \U0001F7E6 Please enter the folder of your scan(Enter the number): ")
        while True:
            try: 
                int(folderid)
            except ValueError:
                print(Fore.RED+" \U0000274C Invalid Selection!\n"+Style.RESET_ALL)
                folderid=input(" \U0001F7E6 Please enter the folder of your scan(Enter the number): ")
            else:
                break

        #Retrieve a list of scans in folder
        print(Fore.CYAN+" \U0001F4C1 Listing your scans...\n")
        listScanUrl = (enter.url+'/scans?folder_id='+folderid)
        listScan = requests.get(url=listScanUrl, headers=head, verify=False)
        jsonScan = listScan.json()
        for data in jsonScan['scans']:
            print(data['name']+' : '+str(data['id']))
        print("\n"+Style.RESET_ALL)

        #fetch scan ID
        scanID=input(" \U0001F7E6 Please enter the scan ID(Enter the number): ")
        while True:
            try:
                int(scanID)
            except ValueError:
                print(Fore.RED+" \U0000274C Invalid Selection!\n"+Style.RESET_ALL)
                scanID=input(" \U0001F7E6 Please enter the scan ID(Enter the number): ")
            else:
                break

        while True:
            clientname = input(" \U0001F7E6 Please enter a name for the requested downloads: ")
            if not clientname:
                print(Fore.RED+" \U0000274C Cannot be blank!\n"+Style.RESET_ALL)
            else:
                break
        
        while True:
            foldername = input(" \U0001F7E6 Please create a folder to store output[Enter name]: ")
            if not foldername:
                print(Fore.RED+" \U0000274C Cannot be blank!\n"+Style.RESET_ALL)
            else:
                break
        

        #create folder
        try:
        # Create target Directory
            os.mkdir(foldername)
            print(Fore.GREEN+" \U00002705 Directory "+foldername+" successfully created!\n "+Style.RESET_ALL) 
        except FileExistsError:
            print(Fore.RED+" \U0000274C Directory "+foldername+" already exists, overwriting...\n"+Style.RESET_ALL)

        

        print(Fore.CYAN+" \U0000231B Now Downloading reports..."+Style.RESET_ALL)
        print("\n")
        print(" \U0000231B Downloading CSV file...")

        #Retrieves the token of the file 
        jsonPayload = json.dumps(datapay)
        scn = requests.post(enter.url+'/scans/'+scanID+'/export', headers=head, data=jsonPayload, verify=False)
        jsonData = scn.json()
        scanToken = str(jsonData['token'])

        #loop to check if the file is ready to download
        status = "Loading"
        while status != 'ready':
            URL = enter.url+"/tokens/"+scanToken+"/status"
            c = requests.get(url=URL, headers=head, verify=False)
            stats = c.json()
            if stats['status'] == 'ready':
                status = 'ready'
            else:
                sleep(4)

        #if the loop is broken then download and save to csv
        file_path = os.path.join(foldername, clientname)
        with requests.get(enter.url+'/tokens/'+scanToken+'/download', headers=head, verify = False) as download:
            open(file_path+'_spreadsheet.csv', 'wb').write(download.content)

        print(Fore.GREEN+" \U00002705 Spreadsheet saved "+"to /"+foldername+Style.RESET_ALL)
        print("\n")
        print(" \U0000231B Downloading Nessus XML file...")

        #pull nessus file
        datanessfile = {
            "format":"nessus"
        }

        DumpNessusData = json.dumps(datanessfile)
        nessfileurl = enter.url+'/scans/'+scanID+'/export'
        reqnessusfile = requests.post(url=nessfileurl, headers=head, data=DumpNessusData, verify=False)
        nessusfilejson = reqnessusfile.json()
        nessusfiletoken = str(nessusfilejson['token'])

        statusd = "Loading"
        while statusd != 'ready':
            URL = enter.url+"/tokens/"+nessusfiletoken+"/status"
            d = requests.get(url=URL, headers=head, verify=False)
            statsd = d.json()
            if statsd['status'] == 'ready':
                statusd = 'ready'
            else:
                sleep(4)
        file_path = os.path.join(foldername, clientname)
        with requests.get(enter.url+'/tokens/'+nessusfiletoken+'/download', headers=head, verify = False) as download:
            open(file_path+'_raw_data.nessus', 'wb').write(download.content)

        print(Fore.GREEN+" \U00002705 Saved Nessus XML file "+"to /"+foldername+Style.RESET_ALL)
        print("\n")
        print(" \U0000231B Downloading PDF's...")

        #for template ID's
        TempURL = enter.url+"/reports/custom/templates"
        getTempID = requests.get(url=TempURL, headers=head, verify=False).json()
        #Loops to find id by name of report
        for a1 in getTempID:
            if a1['name'] == 'Complete List of Vulnerabilities by Host':
                CLOVBH = a1['id']
                break

        for b1 in getTempID:
            if b1['name'] == 'Compliance':
                CPL = b1['id']
                break

        for c1 in getTempID:
            if c1['name'] == 'Detailed Vulnerabilities By Host':
                DVBH = c1['id']
                break

        for d1 in getTempID:
            if d1['name'] == 'Detailed Vulnerabilities By Host with Compliance/Remediations':
                DVBHWCAR = d1['id']
                break

        for e1 in getTempID:
            if e1['name'] == 'Detailed Vulnerabilities By Plugin':
                DVBP = e1['id']
                break

        for f1 in getTempID:
            if f1['name'] == 'Detailed Vulnerabilities By Plugin with Compliance/Remediations':
                DVBPWCR = f1['id']
                break

        for g1 in getTempID:
            if g1['name'] == 'Remediations':
                REM = g1['id']
                break

        for h1 in getTempID:
            if h1['name'] == 'Summary of Exploitable Vulnerabilities':
                SOEV = h1['id']
                break

        for i1 in getTempID:
            if i1['name'] == 'Summary of Hosts with Vulnerabilities':
                SOHWV = i1['id']
                break

        for j1 in getTempID:
            if j1['name'] == 'Summary of Known/Default Accounts':
                SOKDA = j1['id']
                break

        for k1 in getTempID:
            if k1['name'] == 'Summary of Operating Systems':
                SOOS = k1['id']
                break

        for l1 in getTempID:
            if l1['name'] == 'Summary of Unsupported Software':
                SOUS = l1['id']
                break

        for m1 in getTempID:
            if m1['name'] == 'Summary of Vulnerabilities Older Than One Year':
                SOVOTOY = m1['id']
                break

        for n1 in getTempID:
            if n1['name'] == 'Top 10 Vulnerabilities':
                T10V = n1['id']
                break

        for o1 in getTempID:
            if o1['name'] == 'Vulnerability Operations':
                VO = o1['id']
                break

        #Pull PDF Reports
        data_PDF_List_of_Vulnerabilities_by_Host = {
        "format":"pdf",
        "template_id":CLOVBH,
        "csvColumns":{
            
        },
        "formattingOptions":{
            "page_breaks":True
        },
        "extraFilters":{
            "host_ids":[
                
            ],
            "plugin_ids":[
                
            ]
        }
        }

        data_json_dump_846 = json.dumps(data_PDF_List_of_Vulnerabilities_by_Host)
        url_846 = enter.url+'/scans/'+scanID+'/export?limit=2500'
        req_846 = requests.post(url=url_846, headers=head, data=data_json_dump_846, verify=False)
        d846_json = req_846.json()
        d846_token = str(d846_json['token'])
        d846_name = "Complete List of Vulnerabilities by Host"

        status = "Loading"
        while status != 'ready':
            URL = enter.url+"/tokens/"+d846_token+"/status"
            c = requests.get(url=URL, headers=head, verify=False)
            stats = c.json()
            if stats['status'] == 'ready':
                status = 'ready'
            else:
                sleep(4)
        file_path = os.path.join(foldername, clientname)
        with requests.get(enter.url+'/tokens/'+d846_token+'/download', headers=head, verify = False) as download:
            open(file_path+'_'+d846_name+'.pdf', 'wb').write(download.content)

        print(Fore.GREEN+" \U00002705 Downloaded "+d846_name+" to /"+foldername)

        #Pull compliance report
        data_PDF_Compliance = {
        "format":"pdf",
        "template_id":CPL,
        "csvColumns":{
            
        },
        "formattingOptions":{
            "page_breaks":True
        },
        "extraFilters":{
            "host_ids":[
                
            ],
            "plugin_ids":[
                
            ]
        }
        }

        data_json_dump_853 = json.dumps(data_PDF_Compliance)
        url_853 = enter.url+'/scans/'+scanID+'/export'
        req_853 = requests.post(url=url_853, headers=head, data=data_json_dump_853, verify=False)
        req_853_json = req_853.json()
        token_853 = str(req_853_json['token'])
        name_853 = "Compliance"

        status = "Loading"
        while status != 'ready':
            URL = enter.url+"/tokens/"+token_853+"/status"
            f = requests.get(url=URL, headers=head, verify=False)
            stats = f.json()
            if stats['status'] == 'ready':
                status = 'ready'
            else:
                sleep(4)
        
        file_path = os.path.join(foldername, clientname)
        with requests.get(enter.url+'/tokens/'+token_853+'/download', headers=head, verify = False) as download:
            open(file_path+'_'+name_853+'.pdf', 'wb').write(download.content)

        print(Fore.GREEN+" \U00002705 Downloaded "+name_853+" to /"+foldername)

        #download Detailed Vulnerabilities by Host
        data_842 = {
        "format":"pdf",
        "template_id":DVBH,
        "csvColumns":{
            
        },
        "formattingOptions":{
            "page_breaks":True
        },
        "extraFilters":{
            "host_ids":[
                
            ],
            "plugin_ids":[
                
            ]
        }
        }

        data_json_dump_842 = json.dumps(data_842)
        url_842 = enter.url+'/scans/'+scanID+'/export'
        req_842 = requests.post(url=url_842, headers=head, data=data_json_dump_842, verify=False)
        req_842_json = req_842.json()
        token_842 = str(req_842_json['token'])
        name_842 = "Detailed Vulnerabilities by Host"

        status = "Loading"
        while status != 'ready':
            URL = enter.url+"/tokens/"+token_842+"/status"
            g = requests.get(url=URL, headers=head, verify=False)
            stats = g.json()
            if stats['status'] == 'ready':
                status = 'ready'
            else:
                sleep(4)
       
        file_path = os.path.join(foldername, clientname)
        with requests.get(enter.url+'/tokens/'+token_842+'/download', headers=head, verify = False) as download:
            open(file_path+'_'+name_842+'.pdf', 'wb').write(download.content)

        print(Fore.GREEN+" \U00002705 Downloaded "+name_842+" to /"+foldername)

        #Detailed Vulnerabilities by Host with Compliance and Remediations
        data_961 = {
        "format":"pdf",
        "template_id":DVBHWCAR,
        "csvColumns":{
            
        },
        "formattingOptions":{
            "page_breaks":True
        },
        "extraFilters":{
            "host_ids":[
                
            ],
            "plugin_ids":[
                
            ]
        }
        }

        data_json_dump_961 = json.dumps(data_961)
        url_961 = enter.url+'/scans/'+scanID+'/export'
        req_961 = requests.post(url=url_961, headers=head, data=data_json_dump_961, verify=False)
        req_961_json = req_961.json()
        token_961 = str(req_961_json['token'])
        name_961 = "Detailed Vulnerabilities by Host with Compliance and Remediations"

        status = "Loading"
        while status != 'ready':
            URL = enter.url+"/tokens/"+token_961+"/status"
            g = requests.get(url=URL, headers=head, verify=False)
            stats = g.json()
            if stats['status'] == 'ready':
                status = 'ready'
            else:
                sleep(4)
        
        file_path = os.path.join(foldername, clientname)
        with requests.get(enter.url+'/tokens/'+token_961+'/download', headers=head, verify = False) as download:
            open(file_path+'_'+name_961+'.pdf', 'wb').write(download.content)

        print(Fore.GREEN+" \U00002705 Downloaded "+name_961+" to /"+foldername)


        #Detailed Vulnerabilities by Plugin
        data_964 = {
        "format":"pdf",
        "template_id":DVBP,
        "csvColumns":{
            
        },
        "formattingOptions":{
            "page_breaks":True
        },
        "extraFilters":{
            "host_ids":[
                
            ],
            "plugin_ids":[
                
            ]
        }
        }

        data_json_dump_964 = json.dumps(data_964)
        url_964 = enter.url+'/scans/'+scanID+'/export'
        req_964 = requests.post(url=url_964, headers=head, data=data_json_dump_964, verify=False)
        req_964_json = req_964.json()
        token_964 = str(req_964_json['token'])
        name_964 = "Detailed Vulnerabilities by Plugin"

        status = "Loading"
        while status != 'ready':
            URL = enter.url+"/tokens/"+token_964+"/status"
            g = requests.get(url=URL, headers=head, verify=False)
            stats = g.json()
            if stats['status'] == 'ready':
                status = 'ready'
            else:
                sleep(4)
        
        file_path = os.path.join(foldername, clientname)
        with requests.get(enter.url+'/tokens/'+token_964+'/download', headers=head, verify = False) as download:
            open(file_path+'_'+name_964+'.pdf', 'wb').write(download.content)

        print(Fore.GREEN+" \U00002705 Downloaded "+name_964+" to /"+foldername)

        #Detailed Vulnerabilities by Plugin with Complaince and Remediations
        data_963 = {
        "format":"pdf",
        "template_id":DVBPWCR,
        "csvColumns":{
            
        },
        "formattingOptions":{
            "page_breaks":True
        },
        "extraFilters":{
            "host_ids":[
                
            ],
            "plugin_ids":[
                
            ]
        }
        }

        data_json_dump_963 = json.dumps(data_963)
        url_963 = enter.url+'/scans/'+scanID+'/export'
        req_963 = requests.post(url=url_963, headers=head, data=data_json_dump_963, verify=False)
        req_963_json = req_963.json()
        token_963 = str(req_963_json['token'])
        name_963 = "Detailed Vulnerabilities by Plugin with Complaince and Remediations"

        status = "Loading"
        while status != 'ready':
            URL = enter.url+"/tokens/"+token_963+"/status"
            g = requests.get(url=URL, headers=head, verify=False)
            stats = g.json()
            if stats['status'] == 'ready':
                status = 'ready'
            else:
                sleep(4)
        
        file_path = os.path.join(foldername, clientname)
        with requests.get(enter.url+'/tokens/'+token_963+'/download', headers=head, verify = False) as download:
            open(file_path+'_'+name_963+'.pdf', 'wb').write(download.content)

        print(Fore.GREEN+" \U00002705 Downloaded "+name_963+" to /"+foldername)

        #Remediations
        data_975 = {
        "format":"pdf",
        "template_id":REM,
        "csvColumns":{
            
        },
        "formattingOptions":{
            "page_breaks":True
        },
        "extraFilters":{
            "host_ids":[
                
            ],
            "plugin_ids":[
                
            ]
        }
        }

        data_json_dump_975 = json.dumps(data_975)
        url_975 = enter.url+'/scans/'+scanID+'/export'
        req_975 = requests.post(url=url_975, headers=head, data=data_json_dump_975, verify=False)
        req_975_json = req_975.json()
        token_975 = str(req_975_json['token'])
        name_975 = "Remediations"

        status = "Loading"
        while status != 'ready':
            URL = enter.url+"/tokens/"+token_975+"/status"
            g = requests.get(url=URL, headers=head, verify=False)
            stats = g.json()
            if stats['status'] == 'ready':
                status = 'ready'
            else:
                sleep(4)

        file_path = os.path.join(foldername, clientname)
        with requests.get(enter.url+'/tokens/'+token_975+'/download', headers=head, verify = False) as download:
            open(file_path+'_'+name_975+'.pdf', 'wb').write(download.content)

        print(Fore.GREEN+" \U00002705 Downloaded "+name_975+" to /"+foldername)

        #Summary of Exploitable Vulnerabilities 
        data_SOEV = {
        "format":"pdf",
        "template_id":SOEV,
        "csvColumns":{
            
        },
        "formattingOptions":{
            "page_breaks":True
        },
        "extraFilters":{
            "host_ids":[
                
            ],
            "plugin_ids":[
                
            ]
        }
        }

        data_json_dump_SOEV = json.dumps(data_SOEV)
        url_SOEV = enter.url+'/scans/'+scanID+'/export'
        req_SOEV = requests.post(url=url_SOEV, headers=head, data=data_json_dump_SOEV, verify=False)
        req_SOEV_json = req_SOEV.json()
        token_SOEV = str(req_SOEV_json['token'])
        name_SOEV = "Summary of Exploitable Vulnerabilities"

        status = "Loading"
        while status != 'ready':
            URL = enter.url+"/tokens/"+token_SOEV+"/status"
            g = requests.get(url=URL, headers=head, verify=False)
            stats = g.json()
            if stats['status'] == 'ready':
                status = 'ready'
            else:
                sleep(4)

        file_path = os.path.join(foldername, clientname)
        with requests.get(enter.url+'/tokens/'+token_SOEV+'/download', headers=head, verify = False) as download:
            open(file_path+'_'+name_SOEV+'.pdf', 'wb').write(download.content)

        print(Fore.GREEN+" \U00002705 Downloaded "+name_SOEV+" to /"+foldername)

        #Summary of Hosts with Vulnerabilities 
        data_SOHWV = {
        "format":"pdf",
        "template_id":SOHWV,
        "csvColumns":{
            
        },
        "formattingOptions":{
            "page_breaks":True
        },
        "extraFilters":{
            "host_ids":[
                
            ],
            "plugin_ids":[
                
            ]
        }
        }

        data_json_dump_SOHWV = json.dumps(data_SOHWV)
        url_SOHWV = enter.url+'/scans/'+scanID+'/export'
        req_SOHWV = requests.post(url=url_SOHWV, headers=head, data=data_json_dump_SOHWV, verify=False)
        req_SOHWV_json = req_SOHWV.json()
        token_SOHWV = str(req_SOHWV_json['token'])
        name_SOHWV = "Summary of Hosts with Vulnerabilities"

        status = "Loading"
        while status != 'ready':
            URL = enter.url+"/tokens/"+token_SOHWV+"/status"
            g = requests.get(url=URL, headers=head, verify=False)
            stats = g.json()
            if stats['status'] == 'ready':
                status = 'ready'
            else:
                sleep(4)

        file_path = os.path.join(foldername, clientname)
        with requests.get(enter.url+'/tokens/'+token_SOHWV+'/download', headers=head, verify = False) as download:
            open(file_path+'_'+name_SOHWV+'.pdf', 'wb').write(download.content)

        print(Fore.GREEN+" \U00002705 Downloaded "+name_SOHWV+" to /"+foldername)

        #Summary of Known/Default Accounts 
        data_SOKDA = {
        "format":"pdf",
        "template_id":SOKDA,
        "csvColumns":{
            
        },
        "formattingOptions":{
            "page_breaks":True
        },
        "extraFilters":{
            "host_ids":[
                
            ],
            "plugin_ids":[
                
            ]
        }
        }

        data_json_dump_SOKDA = json.dumps(data_SOKDA)
        url_SOKDA = enter.url+'/scans/'+scanID+'/export'
        req_SOKDA = requests.post(url=url_SOKDA, headers=head, data=data_json_dump_SOKDA, verify=False)
        req_SOKDA_json = req_SOKDA.json()
        token_SOKDA = str(req_SOKDA_json['token'])
        name_SOKDA = "Summary of Known and Default Accounts"

        status = "Loading"
        while status != 'ready':
            URL = enter.url+"/tokens/"+token_SOKDA+"/status"
            g = requests.get(url=URL, headers=head, verify=False)
            stats = g.json()
            if stats['status'] == 'ready':
                status = 'ready'
            else:
                sleep(4)

        file_path = os.path.join(foldername, clientname)
        with requests.get(enter.url+'/tokens/'+token_SOKDA+'/download', headers=head, verify = False) as download:
            open(file_path+'_'+name_SOKDA+'.pdf', 'wb').write(download.content)

        print(Fore.GREEN+" \U00002705 Downloaded "+name_SOKDA+" to /"+foldername)

        #Summary of Operating Systems 
        data_SOOS = {
        "format":"pdf",
        "template_id":SOOS,
        "csvColumns":{
            
        },
        "formattingOptions":{
            "page_breaks":True
        },
        "extraFilters":{
            "host_ids":[
                
            ],
            "plugin_ids":[
                
            ]
        }
        }

        data_json_dump_SOOS = json.dumps(data_SOOS)
        url_SOOS = enter.url+'/scans/'+scanID+'/export'
        req_SOOS = requests.post(url=url_SOOS, headers=head, data=data_json_dump_SOOS, verify=False)
        req_SOOS_json = req_SOOS.json()
        token_SOOS = str(req_SOOS_json['token'])
        name_SOOS = "Summary of Operating Systems"

        status = "Loading"
        while status != 'ready':
            URL = enter.url+"/tokens/"+token_SOOS+"/status"
            g = requests.get(url=URL, headers=head, verify=False)
            stats = g.json()
            if stats['status'] == 'ready':
                status = 'ready'
            else:
                sleep(4)

        file_path = os.path.join(foldername, clientname)
        with requests.get(enter.url+'/tokens/'+token_SOOS+'/download', headers=head, verify = False) as download:
            open(file_path+'_'+name_SOOS+'.pdf', 'wb').write(download.content)

        print(Fore.GREEN+" \U00002705 Downloaded "+name_SOOS+" to /"+foldername)

        #Summary of Unsupported Software 
        data_SOUS = {
        "format":"pdf",
        "template_id":SOUS,
        "csvColumns":{
            
        },
        "formattingOptions":{
            "page_breaks":True
        },
        "extraFilters":{
            "host_ids":[
                
            ],
            "plugin_ids":[
                
            ]
        }
        }

        data_json_dump_SOUS = json.dumps(data_SOUS)
        url_SOUS = enter.url+'/scans/'+scanID+'/export'
        req_SOUS = requests.post(url=url_SOUS, headers=head, data=data_json_dump_SOUS, verify=False)
        req_SOUS_json = req_SOUS.json()
        token_SOUS = str(req_SOUS_json['token'])
        name_SOUS = "Summary of Unsupported Software"

        status = "Loading"
        while status != 'ready':
            URL = enter.url+"/tokens/"+token_SOUS+"/status"
            g = requests.get(url=URL, headers=head, verify=False)
            stats = g.json()
            if stats['status'] == 'ready':
                status = 'ready'
            else:
                sleep(4)

        file_path = os.path.join(foldername, clientname)
        with requests.get(enter.url+'/tokens/'+token_SOUS+'/download', headers=head, verify = False) as download:
            open(file_path+'_'+name_SOUS+'.pdf', 'wb').write(download.content)

        print(Fore.GREEN+" \U00002705 Downloaded "+name_SOUS+" to /"+foldername)

        #Summary of Vulnerabilities Older Than One Year 
        data_SOVOTOY = {
        "format":"pdf",
        "template_id":SOVOTOY,
        "csvColumns":{
            
        },
        "formattingOptions":{
            "page_breaks":True
        },
        "extraFilters":{
            "host_ids":[
                
            ],
            "plugin_ids":[
                
            ]
        }
        }

        data_json_dump_SOVOTOY = json.dumps(data_SOVOTOY)
        url_SOVOTOY = enter.url+'/scans/'+scanID+'/export'
        req_SOVOTOY = requests.post(url=url_SOVOTOY, headers=head, data=data_json_dump_SOVOTOY, verify=False)
        req_SOVOTOY_json = req_SOVOTOY.json()
        token_SOVOTOY = str(req_SOVOTOY_json['token'])
        name_SOVOTOY = "Summary of Vulnerabilities Older Than One Year"

        status = "Loading"
        while status != 'ready':
            URL = enter.url+"/tokens/"+token_SOVOTOY+"/status"
            g = requests.get(url=URL, headers=head, verify=False)
            stats = g.json()
            if stats['status'] == 'ready':
                status = 'ready'
            else:
                sleep(4)

        file_path = os.path.join(foldername, clientname)
        with requests.get(enter.url+'/tokens/'+token_SOVOTOY+'/download', headers=head, verify = False) as download:
            open(file_path+'_'+name_SOVOTOY+'.pdf', 'wb').write(download.content)

        print(Fore.GREEN+" \U00002705 Downloaded "+name_SOVOTOY+" to /"+foldername)

        #Top 10 Vulnerabilities 
        data_T10V = {
        "format":"pdf",
        "template_id":T10V,
        "csvColumns":{
            
        },
        "formattingOptions":{
            "page_breaks":True
        },
        "extraFilters":{
            "host_ids":[
                
            ],
            "plugin_ids":[
                
            ]
        }
        }

        data_json_dump_T10V = json.dumps(data_T10V)
        url_T10V = enter.url+'/scans/'+scanID+'/export'
        req_T10V = requests.post(url=url_T10V, headers=head, data=data_json_dump_T10V, verify=False)
        req_T10V_json = req_T10V.json()
        token_T10V = str(req_T10V_json['token'])
        name_T10V = "Top 10 Vulnerabilities"

        status = "Loading"
        while status != 'ready':
            URL = enter.url+"/tokens/"+token_T10V+"/status"
            g = requests.get(url=URL, headers=head, verify=False)
            stats = g.json()
            if stats['status'] == 'ready':
                status = 'ready'
            else:
                sleep(4)

        file_path = os.path.join(foldername, clientname)
        with requests.get(enter.url+'/tokens/'+token_T10V+'/download', headers=head, verify = False) as download:
            open(file_path+'_'+name_T10V+'.pdf', 'wb').write(download.content)

        print(Fore.GREEN+" \U00002705 Downloaded "+name_T10V+" to /"+foldername)

        #Vulnerability Operations 
        data_VO = {
        "format":"pdf",
        "template_id":VO,
        "csvColumns":{
            
        },
        "formattingOptions":{
            "page_breaks":True
        },
        "extraFilters":{
            "host_ids":[
                
            ],
            "plugin_ids":[
                
            ]
        }
        }

        data_json_dump_VO = json.dumps(data_VO)
        url_VO = enter.url+'/scans/'+scanID+'/export'
        req_VO = requests.post(url=url_VO, headers=head, data=data_json_dump_VO, verify=False)
        req_VO_json = req_VO.json()
        token_VO = str(req_VO_json['token'])
        name_VO = "Vulnerability Operations"

        status = "Loading"
        while status != 'ready':
            URL = enter.url+"/tokens/"+token_VO+"/status"
            g = requests.get(url=URL, headers=head, verify=False)
            stats = g.json()
            if stats['status'] == 'ready':
                status = 'ready'
            else:
                sleep(4)

        file_path = os.path.join(foldername, clientname)
        with requests.get(enter.url+'/tokens/'+token_VO+'/download', headers=head, verify = False) as download:
            open(file_path+'_'+name_VO+'.pdf', 'wb').write(download.content)

        print(Fore.GREEN+" \U00002705 Downloaded "+name_VO+" to /"+foldername)
        print("\n")
        print(Fore.GREEN+" \U0001F3C1 All Reports have downloaded successfully."+Style.RESET_ALL)
        print("\n")

        while True:
            yesno2 = input(" \U0001F4CC Do you wish to continue?[y/n]  ")
            yesstrings2 = ["y", "yes", "Y", "Yes"]
            if yesno2 in yesstrings2:
                print(Fore.GREEN+" \U00002705 Continuing...\n"+Style.RESET_ALL)
                break
            elif yesno2 not in yesstrings2:
                print(Fore.YELLOW+" \U0001F44B Thanks for using PullMyReports!"+Style.RESET_ALL)
                print(articles+"\n")
                exit()

start()
