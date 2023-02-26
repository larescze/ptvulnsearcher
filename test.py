"""import requests


request = requests.get("https://cve.circl.lu/api/cve/CVE-1999-0159")
response = request.json()
product_v = response["vulnerable_product"][-1].split(":")[5].split('\\')[0]
print(product_v)"""


#-----------------------------------------------------------------------------------------------------
"""import os



def input_sanitization(input):
    sanitized_input= ""
    potentially_dangerous = ['<','>','\'','\"',"AND","OR","SELECT","UNION","DROP","ALTER","FROM"]
    for content1 in input.split(' '):
        for content2 in potentially_dangerous:
            if (content1 == content2):
                sanitized_input = sanitized_input +"&t"
            else:
                sanitized_input = sanitized_input + content1
    return sanitized_input

inp = input_sanitization("AND")
print(inp)
#Alter this into a function and implement it into to a main code 'api.py'"""
#-----------------------------------------------------------------------------------------------------
"""import argparse
parser = argparse.ArgumentParser()
parser.add_argument("echo", help="enter whatever you want")
args = parser.parse_args()
print(args.echo)"""

#-----------------------------------------------------------------------------------------------------
"""with open('allitems.csv', 'r', encoding='utf-8') as file:
    content = file.readlines()
header1 = content[:10]
header2 = content[10]
print(header1)
print("\n")
print(header2)"""
#-----------------------------------------------------------------------------------------------------
import csv

import requests


def csv_file_reader():

    #Open file and 'cve-id' data into db
    with open('allitems.csv', mode='r', encoding='iso8859') as csv_file:  # Download from https://www.cve.org/Downloads
        reader = csv.DictReader(csv_file)

        next(reader)
        next(reader)
        next(reader)
        next(reader)
        next(reader)
        next(reader)
        next(reader)
        next(reader)
        next(reader)

       
        for line in reader:
            yield line
        
for cve_id in csv_file_reader():
    print(cve_id)
    

#-----------------------------------------------------------------------------------------------------
"""def csv_file_reader():
    with open('allitems.csv', mode='r', encoding='iso8859') as csv_file:  # Download from https://www.cve.org/Downloads
        reader = csv.DictReader(csv_file)

        for i in reader:
            print(i['CVE Version 20061101'])
            

csv_file_reader()"""


#-----------------------------------------------------------------------------------------------------



"""# importing the csv library
import csv
 
# opening the csv file
with open('allitems.csv',encoding='iso8859') as csv_file:
 
        # reading the csv file using DictReader
    csv_reader = csv.DictReader(csv_file)
 
    # converting the file to dictionary
    # by first converting to list
    # and then converting the list to dict
    dict_from_csv = dict(list(csv_reader)[0])
 
    # making a list from the keys of the dict
    list_of_column_names = list(dict_from_csv.keys())
 
    # displaying the list of column names
    print("List of column names : ",
          list_of_column_names)"""





