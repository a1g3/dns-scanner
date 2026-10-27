import csv
import requests
import json
import psycopg2
from datetime import datetime, timezone
from threading import Thread
from psycopg2 import sql
import random
import time

SCANNER_TEXT = os.getenv('DNSSCANNER_CURR_SCAN', 'Scan')

class ScannerThread(Thread):
    
    def __init__(self, group=None, target=None, name=None,
                 args=(), kwargs={}, Verbose=None):
        Thread.__init__(self, group, target, name, args, kwargs)
        self._return = None

    def run(self):
        if self._target is not None:
            self._return = self._target(*self._args,
                                                **self._kwargs)
    def join(self, *args):
        Thread.join(self, *args)
        return self._return

def main():
    # Connect to your postgres DB
    db_user = os.getenv('DNSSCANNER_DB_USER', 'research')
    db_password = os.getenv('DNSSCANNER_DB_PASSWORD', 'CHANGEME!!!!')
    db_host = os.getenv('DNSSCANNER_DB_HOST', 'db')

    conn = psycopg2.connect(f'dbname=securegov user={db_user} password={db_password} host={db_host}')

    # Open a cursor to perform database operations
    cur = conn.cursor()
    cur.execute(sql.SQL('SELECT "Domain" FROM public."Domains" domains where NOT EXISTS (SELECT FROM public."Scans" WHERE "Domain" = domains."Domain" and "Scanner" = %s) LIMIT 200;'),  [SCANNER_TEXT])
    records = cur.fetchall()

    while len(records) != 0:
        for rec in records:
            time.sleep(3)
            url = rec[0]
            if '/' in url:
                url = url.split('/')[0]
            ohiothr = ScannerThread(target=call_api, args=("", rec[0]))
            ohiothr.start()
            ohio_results = ohiothr.join()

            dt = datetime.now(timezone.utc)
            cur.execute(sql.SQL('INSERT INTO public."Scans"("Timestamp", "Results", "Domain", "Scanner", "Region") VALUES (%s, %s, %s, %s, %s)'), [dt, ohio_results, rec[0].lower(), SCANNER_TEXT, "ohio"])
            conn.commit()
            records = []
        cur = conn.cursor()
        cur.execute(sql.SQL('SELECT "Domain" FROM public."Domains" domains where NOT EXISTS (SELECT FROM public."Scans" WHERE "Domain" = domains."Domain" and "Scanner" = %s) LIMIT 200;'),  [SCANNER_TEXT])
        records = cur.fetchall()
    cur.close()
    conn.close()

def call_api(scanner, domain):
    try:
        # sending get request and saving the response as response object
	api_host = os.getenv('DNSSCANNER_API_HOST', 'http://dnsscanner-api:10000')
        r = requests.get(url = f"{api_url}/api/{domain}", verify=False, timeout=60)
        
        # extracting data in json format
        data = r.json()

        print(f"RUNNER: {domain} SUCCESS from {scanner}")

        return json.dumps(data)
    except Exception as er:
        print(f"ERROR: Cannot run scanner on {domain} from {scanner}")
        print(er)
        return "{}"


if __name__ == "__main__":
    main()
