

from argparse import ArgumentParser
from time     import sleep

import json
import requests
import sys
import urllib.parse
import os
import hashlib
import requests
import textwrap
import pyodbc
import re
import openpyxl



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


PWNED_API_URL = "https://haveibeenpwned.com/api/v3/%s/%s?truncateResponse=%s"
HEADERS = {
           "User-Agent": "checkpwnedemails",
           "hibp-api-key": "",
}






EMAILINDEX = 0
PWNEDINDEX = 1
DATAINDEX  = 2

BREACHED = "breachedaccount"
PASTEBIN = "pasteaccount"

RATE_LIMIT = 1.6  # in seconds


# Arguments for the input
class PwnedArgParser(ArgumentParser):
	def error(self, message):
		sys.stderr.write('error: %s\n' %message)
		self.print_help()
		sys.exit(2)

def get_args():
	parser = PwnedArgParser()

	# parser.add_argument('-a', dest='apikey_path',  help='Path to text file that contains your HIBP API key.')
	parser.add_argument('-b', action="store_true", dest='only_breaches', help='Return results for breaches only.')
	parser.add_argument('-i', dest='input_path',   help='Path to text file that lists email addresses.')
	parser.add_argument('-n', action="store_true", dest='names_only', help='Return the name of the breach(es) only.')
	parser.add_argument('-o', dest='output_path',  help='Path to output (tab deliminated) text file.')
	parser.add_argument('-p', action="store_true", dest='only_pwned', help='Print only the pwned email addresses.')
	parser.add_argument('-s', dest="single_email", help='Send query for just one email address.')
	parser.add_argument('-t', action="store_true", dest='only_pastebins', help='Return results for pastebins only.')

	if len(sys.argv) == 1:  # If no arguments were provided, then print help and exit.
		parser.print_help()
		sys.exit(1)

	return parser.parse_args()




#  Used for removing the trailing '\n' character on each email.
def clean_list(list_of_strings):
	return [str(x).strip() for x in list_of_strings]


def printHTTPErrorOutput(http_error_code, hibp_api_key, email=None):
	ERROR_CODE_OUTPUT = {
		400: "HTTP Error 400.  %s does not appear to be a valid email address." % (email),
		401: "HTTP Error 401.  Unauthorised - the API key provided (%s) was not valid." % (hibp_api_key),
		403: "HTTP Error 403.  Forbidden - no user agent has been specified in the request.",
		429: "HTTP Error 429.  Too many requests; the rate limit has been exceeded.",
		503: "HTTP Error 503.  Service unavailable."
	}

	try:
		print(ERROR_CODE_OUTPUT[http_error_code])
	except KeyError:
		print("HTTP Error %s" % (http_error_code))

	if http_error_code == 401:
		sys.exit(1)






def get_results(service, hibp_api_key):
	results = []  # list of tuples (email adress, been pwned?, json data)

	select_sql = "SELECT email FROM [Credentials]"
	crsr.execute(select_sql)

	rows = crsr.fetchall()

	for row in rows:
		print(''.join(row))
		email = ''.join(row)
		response = requests.get(url=PWNED_API_URL % (service, email, True), headers=HEADERS)



		try:

			is_pwned = True


			if response.content:
				data = response.json()
			else:
				data = None   # No results came back for this email.  According to HIBP, this email was not pwned.
				is_pwned = False

			results.append( (email, is_pwned, data) )
		except requests.exceptions.HTTPError as e:
			# if e.code == 404 and not opts.only_pwned:
			if e.code == 404:
				results.append( (email, False, data) )  # No results came back for this email.  According to HIBP, this email was not pwned.
			elif e.code != 404:
				printHTTPErrorOutput(e.code, hibp_api_key, email)



		sleep(RATE_LIMIT)  # This delay is for rate limiting.

		# if not opts.output_path:
		# 	try:
		last_result = results[-1]

		if not last_result[PWNEDINDEX]:
			if service == BREACHED:
				print("Email address %s not pwned.  Yay!\n==========" % (email))
				is_pwned = "No"
				name = "NA"

				query = (
            	"UPDATE Credentials SET is_pwned=(?), name=(?)"
            	"WHERE email=(?)")

				crsr.execute(query, (is_pwned, name, email))

				crsr.commit()

			else:
				print("Email address %s was not found in any pastes.  Yay!" %(email))
		else:
			print("%s pwned!\n==========" % (email))
			is_pwned = "Yes"
			# print(json.dumps(data, indent=4))
			print('\n')
			for s in range(len(data)):
				name = json.dumps(data[s]['Name']).replace('"','')

				

			# name = json.dumps(data[s]['Name'])
			# domain = json.dumps(data[s]['Domain'])
			# breach_date = json.dumps(data[s]['BreachDate'])
			# added_date = json.dumps(data[s]['AddedDate'])
			# modified_date = json.dumps(data[s]['ModifiedDate'])
			# pwncount = json.dumps(data[s]['PwnCount'])
			# is_verified = json.dumps(data[s]['IsVerified'])
			# is_fabricated = json.dumps(data[s]['IsFabricated'])
			# is_sensitive = json.dumps(data[s]['IsSensitive'])
			# is_retired = json.dumps(data[s]['IsRetired'])
			# is_spamlist = json.dumps(data[s]['IsSpamList'])

			print(name)

			# query = (
            # "UPDATE Credentials SET name=(?), domain=(?), breach_date=(?), added_date=(?), pwn_count=(?), is_verified=(?), is_fabricated=(?), is_sensitive=(?), is_retired=(?), is_spamlist=(?)"
            # "WHERE email=(?)")

			# crsr.execute(query, (name, domain, breach_date, added_date, modified_date, pwncount, is_verified, is_fabricated, is_sensitive, is_retired, is_spamlist, email))

			query = (
            "UPDATE Credentials SET is_pwned=(?), name=(?)"
            "WHERE email=(?)")

			crsr.execute(query, (is_pwned, name, email))

			crsr.commit()

			# except IndexError:
			# 	pass

	return results




#  This function will convert every item, in dlist, into a string and
#  encode any unicode strings into an 8-bit string.
def clean_and_encode(dlist):
	cleaned_list = []

	for d in dlist:
		try:
			cleaned_list.append(str(d))
		except UnicodeEncodeError:
			cleaned_list.append(str(d.encode('utf-8')))  # Clean the data.

	return cleaned_list

def tab_delimited_string(data):
	DATACLASSES = 'DataClasses'

	begining_sub_str = data[EMAILINDEX] + '\t' + str(data[PWNEDINDEX])
	output_list      = []

	if data[DATAINDEX]:
		for bp in data[DATAINDEX]:  # bp stands for breaches/pastbins
			d = bp
			
			try:
				flat_data_classes = [str(x) for x in d[DATACLASSES]]
				d[DATACLASSES]    = flat_data_classes
			except KeyError:
				pass  #  Not processing a string for a breach.

			flat_d = clean_and_encode(d.values())
			output_list.append(begining_sub_str + '\t' + "\t".join(flat_d))
	else:
		output_list.append(begining_sub_str)

	return '\n'.join(output_list)

def write_results_to_file(filename, results, opts):
	BREACHESTXT   = "_breaches.txt"
	PASTESTXT     = "_pastes.txt"
	BREACH_HEADER = ("Email Address", "Is Pwned", "Name", "Title", "Domain", "Breach Date", "Added Date", "Modified Date", "Pwn Count", "Description", "Logo Path", "Data Classes", "Is Verified", "Is Fabricated", "Is Sensitive", "Is Retired", "Is SpamList")
	PASTES_HEADER = ("Email Address", "Is Pwned", "ID", "Source", "Title", "Date", "Email Count")

	files = []

	file_headers = {
			BREACHESTXT: "\t".join(BREACH_HEADER),
			PASTESTXT:   "\t".join(PASTES_HEADER)
	}

	if opts.only_breaches:
		files.append(BREACHESTXT)
	elif opts.only_pastebins:
		files.append(PASTESTXT)
	else:
		files.append(BREACHESTXT)
		files.append(PASTESTXT)

	if filename.rfind('.') > -1:
		filename = filename[:filename.rfind('.')]

	for res, f in zip(results, files):
		outfile = open(filename + f, 'w', encoding='utf-8')

		outfile.write(file_headers[f] + '\n')

		for r in res:
			outfile.write(tab_delimited_string(r) + '\n')

		outfile.close()



def main():
	hibp_api_key = "ab674baba0be49b2a32504fec3372068"
	HEADERS["hibp-api-key"] = hibp_api_key
	
	# results 
	results = []
	results.append(get_results(BREACHED, hibp_api_key))

# main
if __name__ == '__main__':
	main()

# Close the connection
cnxn.close()