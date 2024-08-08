import sqlite3
import pandas as pd
import requests

# Step 1: Download the SQLite database file
url = "https://raw.githubusercontent.com/CYB3RMX/MalwareHashDB/main/HashDB"
db_path = "HashDB.sqlite"

response = requests.get(url)
with open(db_path, 'wb') as f:
    f.write(response.content)

# Step 2: Connect to the SQLite database
conn = sqlite3.connect(db_path)

# Step 3: Get a list of all tables in the database
tables = pd.read_sql_query("SELECT name FROM sqlite_master WHERE type='table';", conn)

# Step 4: Initialize an empty dictionary to store dataframes
dfs = {}

# Step 5: For each table, read its content into a DataFrame and store it in the dfs dictionary
for table_name in tables['name']:
    dfs[table_name] = pd.read_sql_query(f"SELECT * FROM {table_name};", conn)

# Step 6: Close the connection
conn.close()

# Step 7: Save each DataFrame to a CSV file
for table_name, df in dfs.items():
    csv_file = f"{table_name}.csv"
    df.to_csv(csv_file, index=False)
    print(f"Saved {table_name} to {csv_file}")
