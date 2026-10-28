import csv
import datetime
import json
import os
import psycopg2
from psycopg2 import sql
import argparse
import logging


def get_secret(secret_path):
  if os.path.exists(secret_path):
    with open(secret_path, "r") as f:
      return f.read().strip()
  return os.environ.get(secret_name)

def updateImportLog(domains, curr, prev, dotGovOnly):
    curr.execute(sql.SQL('SELECT "Domain" FROM public."ImportLog" where "ImportLog"."LastSeen" is NULL;'))
    records = curr.fetchall()
    active_domains = []
    for rec in records:
        active_domains.append(rec[0].lower())
    
    s_active_domains = set(active_domains)
    s_domains = set(domains)
    domains_removed = s_active_domains.difference(s_domains)

    if dotGovOnly:
        for domain in domains_removed:
            if domain.endswith('.gov'):
                logging.info(f"Setting LastSeen for {domain}")
                curr.execute(sql.SQL(f'''Update public."ImportLog" SET "LastSeen" = '{prev}' where "Domain" = '{domain}' and "LastSeen" is NULL;'''))
    else:
        for domain in domains_removed:
            if not domain.endswith('.gov'):
                logging.info(f"Setting LastSeen for {domain}")
                curr.execute(sql.SQL(f'''Update public."ImportLog" SET "LastSeen" = '{prev}' where "Domain" = '{domain}' and "LastSeen" is NULL;'''))


def importGSA(gsa_file_path, connection_string, importlog, prev):
    #"dbname=research user=research password= host=192.168.40.12"
    conn = psycopg2.connect(connection_string)

    # Open a cursor to perform database operations
    cur = conn.cursor()
    domains = []

    with open(gsa_file_path, encoding = "ISO-8859-1") as csvfile:
        line = csv.reader(csvfile, delimiter=',', quotechar='"')
        next(line)
        for row in line:
            # Execute a query
            cur.execute(sql.SQL('SELECT 1 FROM public."Domains" WHERE "Domains"."Domain" = %s'), [row[0].lower()])

            # Retrieve query results
            records = cur.fetchone()
            
            if records == None:
                type = ""
                if "/" in row[0]:
                    error_file = open("errors.txt", "a")
                    error_file.write(f"{row[0].lower()}, {type}, {row[3]}, {row[4]},{row[5]}, {row[6]}, {importlog}\n")
                    continue
                if row[4] == "Local":
                    type = "Local"
                elif row[4] == "County":
                    type = "County"
                elif row[4] == "Federal":
                    type = "Federal"
                elif row[4] == "State":
                    type = "State"
                elif row[4] == "Native Sovereign Nation / Tribal":
                    type = "Native Sovereign Nation"
                elif row[4] == "Regional":
                    type = "Interstate"
                elif row[4] == "Quasigovernmental":
                    type = "Quasigovernmental"
                elif row[4] == "Level unclear, see note":
                    type = "Unknown"
                else:
                    print(row)
                    print(row[4])
                    raise NameError()
                
                if(len(row[1]) == 0):
                    agency = row[7].split("--")[0].strip()
                else:
                    agency = row[1]
                location = row[6]
                if location == "":
                    location = "Unknown"
                
                cur.execute(sql.SQL('INSERT INTO public."Domains"("Domain", "GovernmentType", "Organization", "Location", "Note", "ImportLog", "State") VALUES (%s, %s, %s, %s, %s, %s, %s)'), [row[0].lower(), type, agency, location, row[7], importlog, None])
                cur.execute(sql.SQL('INSERT INTO public."ImportLog"("Domain", "FirstSeen", "LastSeen") VALUES (%s, %s, %s);'), [row[0].lower(), importlog, None])
                logging.info(f"Inserted {row[0].lower()} in domains table: {row}")
            else:
                cur.execute(sql.SQL('SELECT 1 FROM public."ImportLog" WHERE "ImportLog"."Domain" = %s and "ImportLog"."LastSeen" is NULL'), [row[0].lower()])
                records = cur.fetchone()

                if records == None:
                    cur.execute(sql.SQL('INSERT INTO public."ImportLog"("Domain", "FirstSeen", "LastSeen") VALUES (%s, %s, %s);'), [row[0].lower(), importlog, None])
                    logging.info(f"Domain {row[0].lower()} has appeared again")

            domains.append(row[0].lower())  
    updateImportLog(domains, cur, prev, False)
    conn.commit() # <- We MUST commit to reflect the inserted data
    cur.close()
    conn.close()

def importDotgov(dotgov_file_path, connection_string, importlog, prev):
    conn = psycopg2.connect(connection_string)

    # Open a cursor to perform database operations
    cur = conn.cursor()
    domains = []

    with open(dotgov_file_path, encoding = "ISO-8859-1") as csvfile:
        line = csv.reader(csvfile, delimiter=',', quotechar='"')

        next(line)
        for row in line:
            # Execute a query
            cur.execute(sql.SQL('SELECT 1 FROM public."Domains" WHERE "Domains"."Domain" = %s'), [row[0].lower()])
            
            # Retrieve query results
            records = cur.fetchone()
            
            if records == None:
                type = ""
                if "/" in row[0]:
                    error_file = open("errors.txt", "a")
                    error_file.write(f"{row[0].lower()}, {type}, {row[3]}, {row[4]},{row[5]}, {row[6]}, {importlog}\n")
                    continue
                if row[1] == "City" or row[1] == "City - Election" or row[1] == "School district":
                    type = "Local"
                elif row[1] == "County" or row[1] == "County - Election":
                    type = "County"
                elif row[1] == "Federal - Executive" or row[1] == "Federal - Judicial" or row[1] == "Federal - Legislative" or row[1] == "Federal":
                    type = "Federal"
                elif row[1] == "State" or row[1] == "State or territory" or row[1] == "State or territory - Election":
                    type = "State"
                elif row[1] == "Tribal" or row[1] == "Tribal - Election":
                    type = "Native Sovereign Nation"
                elif row[1] == "Interstate":
                    type = "Interstate"
                elif row[1] == "Independent Intrastate":
                    type = "Independent Intrastate"
                elif row[1] == "Special district" or row[1] == "Special district - Election":
                    type = "Unknown"
                else:
                    print(row[1])
                    raise NameError()
                cur.execute(sql.SQL('INSERT INTO public."Domains"("Domain", "GovernmentType", "Organization", "Location", "Note", "ImportLog", "State") VALUES (%s, %s, %s, %s, %s, %s, %s)'), [row[0].lower(), type, row[3], f"{row[4]},{row[5]}", row[6], importlog, None])
                cur.execute(sql.SQL('INSERT INTO public."ImportLog"("Domain", "FirstSeen", "LastSeen") VALUES (%s, %s, %s);'), [row[0].lower(), importlog, None])
                logging.info(f"Inserted {row[0].lower()} in domains table: {row}")
            else:
                cur.execute(sql.SQL('SELECT 1 FROM public."ImportLog" WHERE "ImportLog"."Domain" = %s and "ImportLog"."LastSeen" is NULL'), [row[0].lower()])
                records = cur.fetchone()

                if records == None:
                    cur.execute(sql.SQL('INSERT INTO public."ImportLog"("Domain", "FirstSeen", "LastSeen") VALUES (%s, %s, %s);'), [row[0].lower(), importlog, None])
                    logging.info(f"Domain {row[0].lower()} has appeared again")

            domains.append(row[0].lower())
    updateImportLog(domains, cur, prev, True)
    conn.commit() # <- We MUST commit to reflect the inserted data
    cur.close()
    conn.close()

def main():
    db_user = get_secret(os.getenv('DNSSCANNER_DB_USER', 'research'))
    db_password = get_secret(os.getenv('DNSSCANNER_DB_PASSWORD', 'CHANGEME!!!!'))

    db_host = os.getenv('DNSSCANNER_DB_HOST', 'db')
    conn = f'dbname=securegov user={db_user} password={db_password} host={db_host}'

    curr = os.getenv('DNSSCANNER_CURR_SCAN', 'Scan')
    prev = os.getenv('DNSSCANNER_PREV_SCAN', 'Prev')

    dotgov_file = os.getenv('DNSSCANNER_DOTGOV_FILE', 'current-full.csv')
    gsa_file = os.getenv('DNSSCANNER_GSA_FILE', '1_govt_urls_full.csv')

    logging.basicConfig(level=logging.DEBUG)
    #logging.basicConfig(filename='import.log', filemode='a', level=logging.DEBUG)

    importDotgov(f'/data/dotgov/{dotgov_file}', conn, curr, prev)
    importGSA(f'/data/gsa/{gsa_file}', conn, curr, prev)

    logging.shutdown()

if __name__ == "__main__":
    main()
