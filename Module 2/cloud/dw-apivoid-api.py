# Imports
from __future__ import print_function
import requests
import urllib.parse
import json
import sys
import os
import json
import hashlib
import requests
import textwrap
import pyodbc
import sys
import time
import re
import openpyxl

apivoid_key = "3af5da4d735edcd856838fd7fc51bf546193fa18";

# Give the location of the file
path = "../ioc.xlsx"

# Workbook object is created
wb_obj = openpyxl.load_workbook(path)  

# Specify the Driver
driver = '{ODBC Driver 17 for SQL Server}'

# Specify the Server Name and Database Name
server_name = 'dear-watson'
database_name = 'dear-watson-db'

# Create Server URL
server = '{server_name}.database.windows.net,1433'.format(server_name=server_name)

# Define username and password
username = 'dear-watson-admin'
password = 'dw_my@123'

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
cnxn: pyodbc.Connection = pyodbc.connect(connection_string)

# Create a new Cursor Object from the connection
crsr: pyodbc.Cursor = cnxn.cursor()



def apivoid_urlrep(key, url):
   try:
      r = requests.get(url='https://endpoint.apivoid.com/urlrep/v1/pay-as-you-go/?key='+key+'&url='+urllib.parse.quote(url))
      return json.loads(r.content.decode())
   except:
      return ""


def apivoid_domainrep(key, host):
   try:
      r = requests.get(url='https://endpoint.apivoid.com/domainbl/v1/pay-as-you-go/?key='+key+'&host='+host)
      return json.loads(r.content.decode())
   except:
      return ""


def apivoid_sslrep(key, host):
   try:
      r = requests.get(url='https://endpoint.apivoid.com/sslinfo/v1/pay-as-you-go/?key='+key+'&host='+host)
      return json.loads(r.content.decode())
   except:
      return ""

def apivoid_iprep(key, ip):
   try:
      r = requests.get(url='https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/?key='+key+'&ip='+ip)
      return json.loads(r.content.decode())
   except:
      return ""



def scan_ip():

    select_sql = "SELECT server_ip FROM [IP]"
    crsr.execute(select_sql)

    rows = crsr.fetchall()

    # Read all rows
    for row in rows:

        server_ip = ''.join(row)
        print(server_ip)

        data = apivoid_iprep(apivoid_key, server_ip)


        if(data):
            
            if(data.get('error')):
                print("Error: "+data['error'])
            else:




                hostname = json.dumps(data['data']['report']['information']['reverse_dns'])
                detection_count = json.dumps(str(data['data']['report']['blacklists']['detections']))

                country = json.dumps(str(data['data']['report']['information']['country_name']))
                city = json.dumps(str(data['data']['report']['information']['city_name']))
                latitude = json.dumps(str(data['data']['report']['information']['latitude']))
                longitude = json.dumps(str(data['data']['report']['information']['longitude']))
                isp = json.dumps(data['data']['report']['information']['isp'])
                is_proxy = json.dumps(str(data['data']['report']['anonymity']['is_proxy']))  
                is_tor = json.dumps(str(data['data']['report']['anonymity']['is_tor']))
                is_vpn = json.dumps(str(data['data']['report']['anonymity']['is_vpn']))
                is_hosting = json.dumps(str(data['data']['report']['anonymity']['is_hosting']))


                print(server_ip)


                query = (
                    "UPDATE IP SET hostname=(?), detection_count=(?), country=(?), city=(?), latitude=(?), longitude=(?), isp=(?), is_proxy=(?), is_tor=(?), is_vpn=(?), is_hosting=(?)"
                    "WHERE server_ip=(?)")

                crsr.execute(query, (hostname, detection_count, country, city, latitude, longitude, isp, is_proxy, is_tor, is_vpn, is_hosting, server_ip))

                crsr.commit()



def scan_url():

    select_sql = "SELECT url FROM [History]"
    crsr.execute(select_sql)

    rows = crsr.fetchall()

    for row in rows:

        url = ''.join(row)
        print(url)

        data = apivoid_urlrep(apivoid_key, url)

        if(data):
            
            if(data.get('error')):
                print("Error: "+data['error'])
            else:


                risk_score = json.dumps(str(data['data']['report']['risk_score']['result']))
                suspended = json.dumps(str(data['data']['report']['security_checks']['is_suspended_page']))
                blacklisted = json.dumps(str(data['data']['report']['security_checks']['is_domain_blacklisted']))
                phishing = json.dumps(str(data['data']['report']['security_checks']['is_phishing_heuristic']))
                sinkholed = json.dumps(str(data['data']['report']['security_checks']['is_sinkholed_domain']))
                ex_redirect = json.dumps(str(data['data']['report']['security_checks']['is_external_redirect']))
                pw_field = json.dumps(str(data['data']['report']['security_checks']['is_password_field']))
                crcard_field = json.dumps(str(data['data']['report']['security_checks']['is_credit_card_field']))
                url_short = json.dumps(str(data['data']['report']['site_category']['is_url_shortener']))
                free_host = json.dumps(str(data['data']['report']['site_category']['is_free_hosting']))
                server_ip = json.dumps(str(data['data']['report']['server_details']['ip']))
                server_hostname = json.dumps(str(data['data']['report']['server_details']['hostname']))
                country = json.dumps(str(data['data']['report']['server_details']['country_name']))
                isp = json.dumps(str(data['data']['report']['server_details']['isp']))
               
                print(url)

                query = (
                    "UPDATE History SET risk_score=(?), is_suspended=(?), is_blacklisted=(?), is_phishing=(?), is_sinkhole=(?), is_external=(?), is_password_field=(?), is_payment_field=(?), url_shortner=(?), is_free_host=(?), server_ip=(?), server_hostname=(?), country=(?), isp=(?)"
                    "WHERE url=(?)")

                crsr.execute(query, (risk_score, suspended, blacklisted, phishing, sinkholed, ex_redirect, pw_field, crcard_field, url_short, free_host, server_ip, server_hostname, country, isp, url))

                crsr.commit()

    
def scan_bookmarks():
    select_sql = "SELECT url FROM [Bookmarks]"
    crsr.execute(select_sql)

    rows = crsr.fetchall()

    for row in rows:

        url = ''.join(row)
        print(url)

        data = apivoid_urlrep(apivoid_key, url)

        if(data):
            
            if(data.get('error')):
                print("Error: "+data['error'])
            else:


                risk_score = json.dumps(str(data['data']['report']['risk_score']['result']))
                suspended = json.dumps(str(data['data']['report']['security_checks']['is_suspended_page']))
                blacklisted = json.dumps(str(data['data']['report']['security_checks']['is_domain_blacklisted']))
                phishing = json.dumps(str(data['data']['report']['security_checks']['is_phishing_heuristic']))
                sinkholed = json.dumps(str(data['data']['report']['security_checks']['is_sinkholed_domain']))
                ex_redirect = json.dumps(str(data['data']['report']['security_checks']['is_external_redirect']))
                pw_field = json.dumps(str(data['data']['report']['security_checks']['is_password_field']))
                crcard_field = json.dumps(str(data['data']['report']['security_checks']['is_credit_card_field']))
                url_short = json.dumps(str(data['data']['report']['site_category']['is_url_shortener']))
                free_host = json.dumps(str(data['data']['report']['site_category']['is_free_hosting']))
                server_ip = json.dumps(str(data['data']['report']['server_details']['ip']))
                server_hostname = json.dumps(str(data['data']['report']['server_details']['hostname']))
                country = json.dumps(str(data['data']['report']['server_details']['country_name']))
                isp = json.dumps(str(data['data']['report']['server_details']['isp']))
               
                print(url)

                query = (
                    "UPDATE Bookmarks SET risk_score=(?), is_suspended=(?), is_blacklisted=(?), is_phishing=(?), is_sinkhole=(?), is_external=(?), is_password_field=(?), is_payment_field=(?), url_shortner=(?), is_free_host=(?), server_ip=(?), server_hostname=(?), country=(?), isp=(?)"
                    "WHERE url=(?)")

                crsr.execute(query, (risk_score, suspended, blacklisted, phishing, sinkholed, ex_redirect, pw_field, crcard_field, url_short, free_host, server_ip, server_hostname, country, isp, url))

                crsr.commit()


def scan_domain():

    select_sql = "SELECT domain FROM [Domains]"
    crsr.execute(select_sql)

    rows = crsr.fetchall()

    for row in rows:

        domain = ''.join(row)
        print(domain)

        data = apivoid_domainrep(apivoid_key, domain)
  

        if(data):
            
            if(data.get('error')):
                print("Error: "+data['error'])
            else:


                host = json.dumps(str(data['data']['report']['host']))
                ip = json.dumps(str(data['data']['report']['server']['ip']))
                reverse_dns = json.dumps(str(data['data']['report']['server']['reverse_dns']))
                detection_count = json.dumps(str(data['data']['report']['blacklists']['detections']))

                country = json.dumps(str(data['data']['report']['server']['country_name']))
                city = json.dumps(str(data['data']['report']['server']['city_name']))
                latitude = json.dumps(str(data['data']['report']['server']['latitude']))
                longitude = json.dumps(str(data['data']['report']['server']['longitude']))
                isp = json.dumps(str(data['data']['report']['server']['isp']))
                is_free_host = json.dumps(str(data['data']['report']['site_category']['is_free_hosting']))
                is_url_shortner = json.dumps(str(data['data']['report']['category']['is_url_shortener']))
                is_free_dynamic_dns = json.dumps(str(data['data']['report']['category']['is_free_dynamic_dns']))
            

                print(domain)

                query = (
                    "UPDATE Domains SET host=(?), ip_address=(?), reverse_dns=(?), detection_count=(?), country=(?), city=(?), latitude=(?), longitude=(?), isp=(?), is_free_hosting=(?), is_url_shortner=(?), is_free_dynamic_dns=(?)"
                    "WHERE domain=(?)")

                crsr.execute(query, (host, ip, reverse_dns, detection_count, country, city, latitude, longitude, isp, is_free_host, is_url_shortner, is_free_dynamic_dns, domain))

                crsr.commit()



def scan_ssl():

    select_sql = "SELECT domain FROM [SSL]"
    crsr.execute(select_sql)

    rows = crsr.fetchall()

    # Read all rows
    for row in rows:

        domain = ''.join(row)
        print(domain)

        data = apivoid_sslrep(apivoid_key, domain)

        if(data):
            
            if(data.get('error')):
                print("Error: "+data['error'])
            else:

                
                is_found = json.dumps(str(data['data']['certificate']['found']))
                fingerprint = json.dumps(str(data['data']['certificate']['fingerprint']))
                is_blacklisted = json.dumps(str(data['data']['certificate']['blacklisted']))
                valid_peer = json.dumps(str(data['data']['certificate']['valid_peer']))
                deprecated_issuer = json.dumps(str(data['data']['certificate']['deprecated_issuer']))
                name_match = json.dumps(str(data['data']['certificate']['name_match']))
                expired = json.dumps(str(data['data']['certificate']['expired']))
                valid = json.dumps(str(data['data']['certificate']['valid']))
                name = json.dumps(str(data['data']['certificate']['details']['subject']['name']))
                country = json.dumps(str(data['data']['certificate']['details']['subject']['country']))
                issuer_name = json.dumps(str(data['data']['certificate']['details']['issuer']['common_name']))
                valid_from = json.dumps(str(data['data']['certificate']['details']['validity']['valid_from']))
                valid_to = json.dumps(str(data['data']['certificate']['details']['validity']['valid_to']))
            
                print(domain + " Scanned")

                query = (
                    "UPDATE SSL SET is_found=(?), fingerprint=(?), is_blacklisted=(?), valid_peer=(?), depreciated_issuer=(?), name_match=(?), expired=(?), valid=(?), name=(?), country=(?), common_name=(?), valid_from=(?), valid_to=(?)"
                    "WHERE domain=(?)")

                crsr.execute(query, (is_found, fingerprint, is_blacklisted, valid_peer, deprecated_issuer, name_match, expired, valid, name, country, issuer_name, valid_from, valid_to, domain))

                crsr.commit()


# Main Program            
def main():
    print ('Starting Dear Watson Evidence Analyzing Module...')

    while True:
            try:
                choice = int(input("[?] What do you like to analyze? \
					\n1. IP\n2. URL\n3. Domain\n4. SSL\n5. Bookmarks\n6. Exit\n\n"))

            except ValueError:
                print ('[!] Enter Only a Number')
                continue      
    
            if choice == 1:
                scan_ip()
                break
            if choice == 2:
                scan_url()
                break
            if choice == 3:
                scan_domain()
                break
            if choice == 4:
                scan_ssl()
                break
            if choice == 5:
                scan_bookmarks()
                break
            if choice == 6:
                sys.exit(0)
            else:
                print ('[!] Invalid Choice')


if __name__ == "__main__":
    main()

# Close the connection
cnxn.close()