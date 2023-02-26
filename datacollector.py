#!/usr/bin/python3
import psycopg2
import requests
import csv
import json
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
    
    def db_create_tables(self):
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
                    version TEXT,
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

        with open('allitems.csv', mode='r', encoding='iso8859') as csv_file:  # Download from https://www.cve.org/Downloads
            reader = csv.DictReader(csv_file)

            #Haven't found any other way to skip .csv header
            for i in range(9):
                next(reader)
            
            for line in reader:
                yield line['CVE Version 20061101'] #CVE-####-#### information is gonna be yielded by this
    
    def api_request(self):
        for cve_id in self.csv_file_reader():
            print(cve_id)
            request = requests.get("https://cve.circl.lu/api/cve/%s" % cve_id)
            response = request.json()
        
            line_to_be_inserted = {'cveid':"-", 'cwe':"-", 'cvss_vector':"-",'cvss_score':0.0, 'description':"-", 'product_type':"-",'vendor':"-",'product_name':"-", 'product_version':0.0}

            try:
                line_to_be_inserted['cveid'] = response["id"]
                line_to_be_inserted['cwe'] = response["cwe"]
                line_to_be_inserted['cvss_vector'] = response["cvss-vector"]
                line_to_be_inserted['cvss_score'] = response["cvss"]
                line_to_be_inserted['description'] = response["summary"]
                line_to_be_inserted['product_type'] = response["vulnerable_product"][-1].split(":")[2].upper() #Application. OS, . . . 
                line_to_be_inserted['vendor'] = response["vulnerable_product"][-1].split(":")[3].title()    #title() capitalize first letter of the record
                line_to_be_inserted['product_name'] = response["vulnerable_product"][-1].split(":")[4]
                line_to_be_inserted['product_version'] = response["vulnerable_product"][-1].split(":")[5].split('\\')[0]
            except Exception:
                "-"
            
                
            yield line_to_be_inserted
   

    def db_insert(self):
        
        db_connection = self.connection()
   
        cve_table_insert = db_connection.cursor() #'cve_table_update' cursor to handle UPDATEs of 'cve' table
        vendor_table_insert = db_connection.cursor() #'vendor_table_update' cursor to handle UPDATEs of 'vendor' table

        #record_number = 1 #Used for determination of which line is being UPDATEd
        request_counter = 1 #Used to control how many requests have been made already and set the limit for the PAUSE

        for line in self.api_request():
            cve_table_insert.execute("INSERT INTO  cve (cve_id, cwe_id, cvss_vector, cvss_score, description) VALUES (%s, %s, %s, %s, %s)", (line['cveid'],line['cwe'], line['cvss_vector'], line['cvss_score'], line['description'], ))
            vendor_table_insert.execute("INSERT INTO vendor (vendor, product_type, product_name, version) VALUES (%s, %s, %s, %s)", (line['vendor'], line['product_type'],line['product_name'], line['product_version'], ))
            print("Record: %s has been inserted" % line['cveid'])
            request_counter = request_counter + 1 
            if request_counter == 181:
                print("PAUSED FOR 60s")
                sleep(60)
                request_counter = 1
        
        cve_table_insert.close()
        vendor_table_insert.close()
        db_connection.close()
                
                
            
instance = DataCollector()
instance.db_create_tables()
instance.csv_file_reader()
instance.api_request()
instance.db_insert()

