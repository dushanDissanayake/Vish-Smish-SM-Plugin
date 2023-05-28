import textwrap
import pyodbc

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
cnxn: pyodbc.Connection = pyodbc.connect(connection_string)

# Create a new Cursor Object from the connection
crsr: pyodbc.Cursor = cnxn.cursor()

# Define a SELECT query
select_sql = "SELECT * FROM [Customers]"

# Execute the SELECT query
crsr.execute(select_sql)

# Grab the data and print
print(crsr.fetchall())

# Close the connection
cnxn.close()


#   # Drop previous table of same name if one exists
#   cursor.execute("DROP TABLE IF EXISTS inventory;")
#   print("Finished dropping table (if existed).")

#   # Create table
#   cursor.execute("CREATE TABLE inventory (id serial PRIMARY KEY, name VARCHAR(50), quantity INTEGER);")
#   print("Finished creating table.")

#   # Insert some data into table
#   cursor.execute("INSERT INTO inventory (name, quantity) VALUES (%s, %s);", ("banana", 150))
#   print("Inserted",cursor.rowcount,"row(s) of data.")
#   cursor.execute("INSERT INTO inventory (name, quantity) VALUES (%s, %s);", ("orange", 154))
#   print("Inserted",cursor.rowcount,"row(s) of data.")
#   cursor.execute("INSERT INTO inventory (name, quantity) VALUES (%s, %s);", ("apple", 100))
#   print("Inserted",cursor.rowcount,"row(s) of data.")

#   # Cleanup
#   cnxn.commit()
#   cursor.close()
#   cnxn.close()
#   print("Done.")

#   # Read data
#   cursor.execute("SELECT * FROM inventory;")
#   rows = cursor.fetchall()
#   print("Read",cursor.rowcount,"row(s) of data.")

#   # Print all rows
#   for row in rows:
#   	print("Data row = (%s, %s, %s)" %(str(row[0]), str(row[1]), str(row[2])))