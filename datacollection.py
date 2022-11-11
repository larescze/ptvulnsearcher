import json
import psycopg2
import requests
import csv

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
        except:
            print("Connection failed")



    def csv_file_reader(self):
        """Function reads CVE records (CVE-####-####,) from CSV file and puts it into database column 'cve_id' """

        #Database connection
        db_connection = self.connection() #'self' substitute the object instance itself

        #Open file and 'cve-id' data into db
        with open('allitems.csv', mode='r', encoding='cp437') as csv_file:  # Download from https://www.cve.org/Downloads
            reader = csv.reader(csv_file)

            # Used to skip CSV header -> Using  'reader = csv.DictReader(csvfile)' won't strip the header 
            next(reader, None)
            next(reader, None)
            next(reader, None)
            next(reader, None)
            next(reader, None)
            next(reader, None)
            next(reader, None)
            next(reader, None)
            next(reader, None)
            next(reader, None)

            #'cursor' allows Python code to execute PostgreSQL commands in a database session.
            cve_table_cursor = db_connection.cursor() # Cursor for 'cve' table
            vendor_table_cursor = db_connection.cursor() # Cursor for 'vendor' table

            for lines in reader:
                cve_table_cursor.execute("INSERT INTO cve (cve_id) VALUES (%s)", (lines[0],))
                vendor_table_cursor.execute("INSERT INTO vendor (cve_id) VALUES (%s)", (lines[0],))

                
                

            print("Data have been successfully inserted ")
            cve_table_cursor.close()
            vendor_table_cursor.close()
            db_connection.close()




    def cve_api_requests(self):
        """Function reads records from 'cve_id'column of 'cve' table and makes a request based on the values.
        Then, cve_id, cvss_vectro, cvss_score and description data are taken from the response and inserted into tables within the database."""

        #Database connection
        db_connection = self.connection()

        
        #Cursors need to be defined out of if/else statement otherwise 'UnboundLocalError: local variable 'cursor' referenced before assignment' is raised

        cve_table_reading = db_connection.cursor() #'cve_table_reading' cursor for reading 'cve_id' column from DB
        cve_table_update = db_connection.cursor() #'cve_table_update' cursor to handle UPDATEs of 'cve' table
        vendor_table_update = db_connection.cursor() #'vendor_table_update' cursor to handle UPDATEs of 'vendor' table

        #Reading 'cve_id' column's records on which the requests are based
        cve_table_reading.execute("SELECT cve_id FROM cve") 

        #To determine the record that is being updated
        record_number = 1 

        while(True):
            cve_id_record = [row for row in cve_table_reading.fetchone()]
            if(cve_id_record[0][10]=="1" and cve_id_record[0][12]=="1"): #If you reach record 101 -> stop
                break
                
            else:
                record = cve_id_record[0]   # CVE-####-####
                
                #Making request
                request = requests.get("https://cve.circl.lu/api/cve/%s" % record)
                print("Request on: %s" % record)
                
                #Getting response back in JSON format 
                response = request.json()

                #Picking data from JSON response
                try:
                    cwe = response["cwe"]
                except KeyError:
                    cwe = "None"

                try:
                    cvss_v = response["cvss-vector"]
                except KeyError:
                    cvss_v = "None"

                try:
                    cvss_s = response["cvss"]
                except KeyError:
                    cvss_s = "None"

                try:
                    description = response["summary"]
                except KeyError:
                    description = "None"

                #Data for 'vendor' table
                try:
                    product_t = response["vulnerable_product"][-1].split(":")[2].upper() #Application. OS, . . . 
                except KeyError:
                    product_t = "None"
                except IndexError:
                    product_t = "None"
                
                try:
                    vendor = response["vulnerable_product"][-1].split(":")[3].title() #title() capitalize first letter of the record

                except KeyError:
                    vendor = "None"
                except IndexError:
                    product_t = "None"

                try:
                    product_n = response["vulnerable_product"][-1].split(":")[4]
                except KeyError:
                    product_n = "None"
                except IndexError:
                    product_t = "None"
                
                try:
                    product_v = response["vulnerable_product"][-1].split(":")[5]
                except KeyError:
                    product_v = "None"
                except IndexError:
                    product_t = "None"
        
                #Trying UPDATEs
                cve_table_update_query = """UPDATE cve SET cwe_id = %s, cvss_vector = %s, cvss_score = %s, description = %s WHERE id = %s"""
                cve_table_update.execute(cve_table_update_query, (cwe,cvss_v,cvss_s,description, record_number))
                
                vendor_table_update_query = """UPDATE vendor SET vendor = %s, product_type = %s, product_name = %s, version = %s WHERE product_id = %s"""
                vendor_table_update.execute(vendor_table_update_query, (vendor, product_t,product_n, product_v, record_number))
                record_number=record_number+1 #Move to next line

        request.close() #Close session with the server
        cve_table_reading.close()
        cve_table_update.close()
        vendor_table_update.close()
        db_connection.close()



#An instance of 'DataCollector' class
instance = DataCollector()

#Calling class methods
instance.csv_file_reader()
instance.cve_api_requests()
