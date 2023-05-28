from __future__ import print_function
import json
import hashlib
import requests
from virus_total_apis import PublicApi as VirusTotalPublicApi
import textwrap
import pyodbc
import sys

# Specify the Driver
driver = '{ODBC Driver 17 for SQL Server}'

# Specify the Server Name and Database Name
server_name = 'dear-watson'
database_name = 'raw-evidence-db'

# Create Server URL
server = '{server_name}.database.windows.net,1433'.format(server_name=server_name)

# Define username and password
username = 'dearWatsonAdmin'
password = 'Gsmrat@123'

# Create the full connection string
connection_string = textwrap.dedent('''
    Driver={driver};
    Server={server};
    Database={database};
    Uid={username};
    Pwd={password};
    Encrypt=yes;
    TrustServerCertificate=no;
    Connection Timeout=30;
'''.format(
    driver=driver,
    server=server,
    database=database_name,
    username=username,
    password=password
))

# Create a new PYODBC connection object
# cnxn: pyodbc.Connection = pyodbc.connect(connection_string)

# Create a new Cursor Object from the connection
# crsr: pyodbc.Cursor = cnxn.cursor()

# Define a SELECT query
select_sql = "SELECT * FROM [Customers]"

# Execute the SELECT query
# crsr.execute(select_sql)

# Grab the data and print
# print(crsr.fetchall())



# Defining Public API KEY
API_KEY = '0ba7ac4f8bebabf8c4773b58780a21a8c43ab284850b53c357d1a654fe847577'
vt = VirusTotalPublicApi(API_KEY)

# Get MD5 of the file
EICAR = "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".encode('utf-8')
EICAR_MD5 = hashlib.md5(EICAR).hexdigest()

# Scanning IPs
def ipScan(ioc):
    Scan_IP = ioc
    response = vt.get_ip_report(Scan_IP)
    print(json.dumps(response, sort_keys=False, indent=4))

# Scanning files
def fileScan(ioc):
    Scan_file = ioc
    response = vt.get_file_report(Scan_file)

    md5 = json.dumps(response['results']['positives'])
    sha1 = json.dumps(response['results']['sha1'])
    sha256 = json.dumps(response['results']['sha256'])
    detections = json.dumps(response['results']['positives'])
    file_name = 'explorer.exe'

    # add_data = "INSERT INTO [file_hash] values (?, ?, ?, ?, ?, ?)"
    # data_word = (ioc,md5,sha1,sha256,detections,file_name)

    # crsr.execute(add_data,data_word)

    # crsr.commit()

# Scanning URLs
def domainScan(ioc):
    Scan_file = ioc
    response = vt.get_domain_report(Scan_file)
    print(json.dumps(response, sort_keys=False, indent=4))

# Scanning URLs
def urlScan(ioc):
    Scan_URL = ioc
    response = vt.get_url_report(Scan_URL)
    print(json.dumps(response, sort_keys=False, indent=4))


def main():
    print ('Starting Dear Watson Evidence Analyzing Module...')

    while True:
            try:
                choice = int(input("[?] What do you like to analyze? \
					\n1. IP\n2. File Hash\n3. Domain\n4. URL\n5. Exit\n\n"))
                ioc = input("[?] Enter the IOC : ")
            except ValueError:
                print ('[!] Enter Only a Number')
                continue      
    
            if choice == 1:
                ipScan(ioc)
                break
            if choice == 2:
                fileScan(ioc)
                break
            if choice == 3:
                domainScan(ioc)
                break
            if choice == 4:
                urlScan(ioc)
                break
            if choice == 5:
                sys.exit(0)
            else:
                print ('[!] Invalid Choice')


if __name__ == "__main__":
    main()

# Close the connection
# cnxn.close()