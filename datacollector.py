import json
import psycopg2
import requests
import csv
from time import sleep

class DataCollector:

    def __init__(self):
        pass

    def connection(self):
        """Function responsible for database connection"""
        try:
            conn = psycopg2.connect(
                host="localhost",
                port="5432",
                user="postgres",
                password="postgres",
                database="postgres",
                options="-c search_path=dbo,public")
            conn.autocommit = True
            print("Connected")
            return conn
        except Exception as e:
            print("Connection failed\n")
            print(e)
    
    def create_tables(self):
        """Function responsible for creation of tables within the database"""
        try:
            db_connection = self.connection()
            tables_creation_cursor = db_connection.cursor()
            tables_creation_cursor.execute(
                """
                DROP TABLE IF EXISTS public.cve, public.vendor;
                
                CREATE TABLE public."cve"
                (
                    id BIGSERIAL PRIMARY KEY,
                    cve_id VARCHAR(17),           
                    cwe_id VARCHAR(15),		  	
                    cvss_vector VARCHAR(40),
                    cvss_score FLOAT,     
                    description TEXT
                );

                CREATE TABLE public."vendor"
                (
                    product_id SERIAL PRIMARY KEY,
                    cveid BIGSERIAL,
                    vendor TEXT,                    
                    product_type VARCHAR(11),              
                    product_name TEXT,           
                    version VARCHAR(10),
                    FOREIGN KEY (cveid) REFERENCES cve(id)
                );
                """)
            print("Tables were succesfully created")
        except Exception as e:
            print("Creation/Drop failed\n")
            print(e)
        finally:
            tables_creation_cursor.close()
            db_connection.close()


    def csv_file_reader(self):
        """Function reads CVE values (CVE-####-####,) from CSV file and populates 'cve_id' column with them"""

        #Database connection
        db_connection = self.connection()

        #Open file and 'cve-id' data into db
        with open('allitems.csv', mode='r', encoding='cp437') as csv_file:  # Download from https://www.cve.org/Downloads
            reader = csv.reader(csv_file)

            # Used to skip CSV header -> Using  'reader = csv.DictReader(csvfile)' won't strip the header 
            for i in range(10):
                next(reader, None)
        
            #'cursor' allows Python code to execute SQL queries in a database session.
            cve_table_cursor = db_connection.cursor() # Cursor for 'cve' table
            vendor_table_cursor = db_connection.cursor() # Cursor for 'vendor' table

            for lines in reader:
                cve_table_cursor.execute("INSERT INTO cve (cve_id) VALUES (%s)", (lines[0],))

            print("Data have been successfully inserted ")
            cve_table_cursor.close()
            vendor_table_cursor.close()
            db_connection.close()

    def cve_api_requests(self):
        """Function reads values of'cve_id'column of 'cve' table and makes a request based on them.
           Then, cve_id, cvss_vector, cvss_score and description data are taken from the response and are inserted into database."""
        try:
            #Database connection
            db_connection = self.connection()
    
            #Cursors need to be defined out of if/else statement otherwise 'UnboundLocalError: local variable 'cursor' referenced before assignment' is raised
            cve_table_reading = db_connection.cursor() #'cve_table_reading' cursor for reading 'cve_id' column from DB
            cve_table_update = db_connection.cursor() #'cve_table_update' cursor to handle UPDATEs of 'cve' table
            vendor_table_insert = db_connection.cursor() #'vendor_table_update' cursor to handle UPDATEs of 'vendor' table

            #Reading 'cve_id' column values on which the requests are based
            cve_table_reading.execute("SELECT cve_id FROM cve") 

            record_number = 1 #Used for determination of which line is being UPDATEd
            request_counter = 1 #Used to control how many requests have been made already and set the limit for the PAUSE

            while(True):
                cve_id_record = [row for row in cve_table_reading.fetchone()]
                record = cve_id_record[0]   # = CVE-####-####
                
                #Making request
                request = requests.get("https://cve.circl.lu/api/cve/%s" % record)
                print("Request on: %s" % record)
                    
                #Getting response back in JSON format 
                response = request.json()
                
                #This line is used to handle situation when one or more keys of response ('cwe',cvss_v . . . ) aren't present in a response. Because i do not handle the Exception that is risen then, data, from request before are left and not overridden by the new one, because it's not there -> that's why i'am setting the values initially and letting them be overridden, so if no values is present in response the initial 'None' or 0.0 remains.
                (cwe,cvss_v,cvss_s,description,product_t,vendor,product_n,product_v) = ("None","None",0.0,"None","None","None","None",0.0)

                #Picking data from JSON response
                try:
                    cwe = response["cwe"]
                    cvss_v = response["cvss-vector"]
                    cvss_s = response["cvss"]
                    description = response["summary"]
                    product_t = response["vulnerable_product"][-1].split(":")[2].upper() #Application. OS, . . . 
                    vendor = response["vulnerable_product"][-1].split(":")[3].title()    #title() capitalize first letter of the record
                    product_n = response["vulnerable_product"][-1].split(":")[4]
                    product_v = response["vulnerable_product"][-1].split(":")[5].split('\\')[0]
                except Exception:
                    None

                cve_table_update.execute("UPDATE cve SET cwe_id=%s, cvss_vector=%s, cvss_score=%s, description=%s WHERE id=%s", (cwe, cvss_v, cvss_s, description, record_number, ))
                vendor_table_insert.execute("INSERT INTO vendor (vendor, product_type, product_name, version) VALUES (%s, %s, %s, %s)", (vendor, product_t,product_n, product_v,))
                
                request.close()
                record_number=record_number+1 #Move to next line
                request_counter=request_counter+1
                
                if request_counter == 181:
                    sleep(60)
                    request_counter = 1
                
        finally:
            cve_table_reading.close()
            cve_table_update.close()
            vendor_table_insert.close()
            db_connection.close()
        



#An instance of 'DataCollector' class
instance = DataCollector()
#Calling class methods
instance.create_tables()
instance.csv_file_reader()
instance.cve_api_requests()

