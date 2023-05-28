from __future__ import print_function
from OTXv2 import OTXv2
import argparse
import hashlib
import IndicatorTypes
import json
import requests
import textwrap
import pyodbc
import sys
import time
import re


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

# Your API key
API_KEY = '859db9fe4cdaf53c9e9ce1d3353caf89c47794e0b9121f469fad0ff299e9d00c'
OTX_SERVER = 'https://otx.alienvault.com/'
otx = OTXv2(API_KEY, server=OTX_SERVER)

parser = argparse.ArgumentParser(description='OTX CLI Example')
parser.add_argument('-ip', help='IP eg; 4.4.4.4', required=False)
parser.add_argument('-host',
                    help='Hostname eg; www.alienvault.com', required=False)
parser.add_argument(
    '-url', help='URL eg; http://www.alienvault.com', required=False)
parser.add_argument(
    '-hash', help='Hash of a file eg; 7b42b35832855ab4ff37ae9b8fa9e571', required=False)
parser.add_argument(
    '-file', help='Path to a file, eg; malware.exe', required=False)

args = vars(parser.parse_args())


def getValue(results, keys):
    if type(keys) is list and len(keys) > 0:

        if type(results) is dict:
            key = keys.pop(0)
            if key in results:
                return getValue(results[key], keys)
            else:
                return None
        else:
            if type(results) is list and len(results) > 0:
                return getValue(results[0], keys)
            else:
                return results
    else:
        return results



def hostname():

    select_sql = "SELECT domain FROM [Domains]"
    crsr.execute(select_sql)

    rows = crsr.fetchall()

    # Read all rows
    for row in rows:
        hostname = ''.join(row)
        print(hostname)
        response = otx.get_indicator_details_by_section(IndicatorTypes.DOMAIN, hostname, 'general')


        # Return nothing if it's in the whitelist
        validation = getValue(response, ['validation'])
        if not validation:
            pulses = getValue(response, ['pulse_info', 'pulses'])
            if pulses:
                threat = "Yes"
                print(threat)
                print("Domain")
                query = (
                "UPDATE Domains SET is_threat=(?)"
                "WHERE domain=(?)")

                crsr.execute(query, (threat, hostname))

                crsr.commit()

            else:

                response = otx.get_indicator_details_by_section(IndicatorTypes.HOSTNAME, hostname, 'general')
                # Return nothing if it's in the whitelist
                validation = getValue(response, ['validation'])
                if not validation:
                    pulses = getValue(response, ['pulse_info', 'pulses'])
                    if pulses:
                        threat = "Yes"
                        print(threat)
                        print("Host")
                        query = (
                        "UPDATE Domains SET is_threat=(?)"
                        "WHERE domain=(?)")

                        crsr.execute(query, (threat, hostname))

                        crsr.commit()

                    else:
                        threat = "No"
                        print(threat)

                        query = (
                        "UPDATE Domains SET is_threat=(?)"
                        "WHERE domain=(?)")

                        crsr.execute(query, (threat, hostname))

                        crsr.commit()


def ip():

    select_sql = "SELECT server_ip FROM [IP]"
    crsr.execute(select_sql)

    rows = crsr.fetchall()

    # Read all rows
    for row in rows:
        ip = ''.join(row)
        print(ip)
        response = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, ip, 'general')

        # Return nothing if it's in the whitelist
        validation = getValue(response, ['validation'])
        if not validation:
            pulses = getValue(response, ['pulse_info', 'pulses'])
            if pulses:
                threat = "Yes"
                print(threat)
                query = (
                "UPDATE IP SET is_threat=(?)"
                "WHERE server_ip=(?)")

                crsr.execute(query, (threat, ip))

                crsr.commit()

            else:
                threat = "No"
                print(threat)

                query = (
                "UPDATE IP SET is_threat=(?)"
                "WHERE server_ip=(?)")

                crsr.execute(query, (threat, ip))

                crsr.commit()



def url():

    select_sql = "SELECT url FROM [History]"
    crsr.execute(select_sql)

    rows = crsr.fetchall()

    # Read all rows
    for row in rows:
        url = ''.join(row)
        print(url)
        response = otx.get_indicator_details_full(IndicatorTypes.URL, url)

        # Return nothing if it's in the whitelist
        google = getValue( response, ['url_list', 'url_list', 'result', 'safebrowsing'])
        
        if google and 'response_code' in str(google):

        # validation = getValue(response, ['validation'])
        # if not validation:
        #     pulses = getValue(response, ['pulse_info', 'pulses'])
        #     if pulses:
            threat = "Yes"
            print(threat)
            query = (
            "UPDATE History SET is_threat=(?)"
            "WHERE url=(?)")

            crsr.execute(query, (threat, url))

            crsr.commit()

        else:
            threat = "No"
            print(threat)

            query = (
            "UPDATE History SET is_threat=(?)"
            "WHERE url=(?)")

            crsr.execute(query, (threat, url))

            crsr.commit()

    
def bookmarks():

    select_sql = "SELECT url FROM [Bookmarks]"
    crsr.execute(select_sql)

    rows = crsr.fetchall()

    # Read all rows
    for row in rows:
        url = ''.join(row)
        print(url)
        response = otx.get_indicator_details_full(IndicatorTypes.URL, url)

        # Return nothing if it's in the whitelist
        google = getValue( response, ['url_list', 'url_list', 'result', 'safebrowsing'])
        
        if google and 'response_code' in str(google):

        # validation = getValue(response, ['validation'])
        # if not validation:
        #     pulses = getValue(response, ['pulse_info', 'pulses'])
        #     if pulses:
            threat = "Yes"
            print(threat)
            query = (
            "UPDATE Bookmarks SET is_threat=(?)"
            "WHERE url=(?)")

            crsr.execute(query, (threat, url))

            crsr.commit()

        else:
            threat = "No"
            print(threat)

            query = (
            "UPDATE Bookmarks SET is_threat=(?)"
            "WHERE url=(?)")

            crsr.execute(query, (threat, url))

            crsr.commit()




    # alerts = []
    # result = otx.get_indicator_details_full(IndicatorTypes.URL, url)

    # google = getValue( result, ['url_list', 'url_list', 'result', 'safebrowsing'])
    # if google and 'response_code' in str(google):
    #     alerts.append({'google_safebrowsing': 'malicious'})


    # clamav = getValue( result, ['url_list', 'url_list', 'result', 'multiav','matches','clamav'])
    # if clamav:
    #         alerts.append({'clamav': clamav})

    # avast = getValue( result, ['url_list', 'url_list', 'result', 'multiav','matches','avast'])
    # if avast:
    #     alerts.append({'avast': avast})

    # # Get the file analysis too, if it exists
    # has_analysis = getValue( result,  ['url_list','url_list', 'result', 'urlworker', 'has_file_analysis'])
    # if has_analysis:
    #     hash = getValue( result,  ['url_list','url_list', 'result', 'urlworker', 'sha256'])
    #     file_alerts = file(otx, hash)
    #     if file_alerts:
    #         for alert in file_alerts:
    #             alerts.append(alert)

    # # Todo: Check file page

    # return alerts






def file():

    select_sql = "SELECT source_hash FROM [Downloads]"
    crsr.execute(select_sql)

    rows = crsr.fetchall()


    for row in rows:
        source_hash = ''.join(row)
        print(source_hash)


        hash_type = IndicatorTypes.FILE_HASH_MD5
        if len(source_hash) == 64:
            hash_type = IndicatorTypes.FILE_HASH_SHA256
        if len(source_hash) == 40:
            hash_type = IndicatorTypes.FILE_HASH_SHA1

        result = otx.get_indicator_details_full(hash_type, source_hash)

        # avg = getValue( result, ['analysis','analysis','plugins','avg','results','detection'])
        # if avg:
        #     alerts.append({'avg': avg})

        # clamav = getValue( result, ['analysis','analysis','plugins','clamav','results','detection'])
        # if clamav:
        #     alerts.append({'clamav': clamav})

        # avast = getValue( result, ['analysis','analysis','plugins','avast','results','detection'])
        # if avast:
        #     alerts.append({'avast': avast})

        microsoft = getValue( result, ['analysis','analysis','plugins','cuckoo','result','virustotal','scans','Symantec','result'])
        if microsoft:

            threat = "Yes"
            print(threat)
            query = (
            "UPDATE Downloads SET is_threat=(?)"
            "WHERE source_hash=(?)")

            crsr.execute(query, (threat, source_hash))

            crsr.commit()

        else:
            threat = "No"
            print(threat)

            query = (
            "UPDATE Downloads SET is_threat=(?)"
            "WHERE source_hash=(?)")

            crsr.execute(query, (threat, source_hash))

            crsr.commit()

        # symantec = getValue( result, ['analysis','analysis','plugins','cuckoo','result','virustotal','scans','Symantec','result'])
        # if symantec:
        #     alerts.append({'symantec': symantec})

        # kaspersky = getValue( result, ['analysis','analysis','plugins','cuckoo','result','virustotal','scans','Kaspersky','result'])
        # if kaspersky:
        #     alerts.append({'kaspersky': kaspersky})

        # suricata = getValue( result, ['analysis','analysis','plugins','cuckoo','result','suricata','rules','name'])
        # if suricata and 'trojan' in str(suricata).lower():
        #     alerts.append({'suricata': suricata})
    


if args['ip']:
    alerts = ip(otx, args['ip'])
    if len(alerts) > 0:
        print('Identified as potentially malicious')
        print(str(alerts))

    else:
        print('Unknown or not identified as malicious')




if args['host']:
    alerts = hostname(otx, args['host'])
    if len(alerts) > 0:
        print('Identified as potentially malicious')
        print(str(alerts))
    else:
        print('Unknown or not identified as malicious')



if args['url']:
    alerts = url(otx, args['url'])
    if len(alerts) > 0:
        print('Identified as potentially malicious')
        print(str(alerts))
    else:
        print('Unknown or not identified as malicious')

        

if args['hash']:
    alerts =  file(otx, args['hash'])
    if len(alerts) > 0:
        print('Identified as potentially malicious')
        print(str(alerts))
    else:
        print('Unknown or not identified as malicious')




if args['file']:
    hash = hashlib.md5(open(args['file'], 'rb').read()).hexdigest()
    alerts =  file(otx, hash)
    if len(alerts) > 0:
        print('Identified as potentially malicious')
        print(str(alerts))
    else:
        print('Unknown or not identified as malicious')




def main():
    # ip()
    # hostname()
    # url()
    # bookmarks()
    file()





if __name__ == "__main__":
    main()



# Close the connection
cnxn.close()
