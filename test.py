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
"""import argparse

parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers()
search = subparsers.add_parser('search')
search.add_argument('--cve')
search.add_argument('--vendor')
args = parser.parse_args()

if args.cve and args.vendor:
    print(args.cve,args.vendor)
else:
    print("/")"""

#-----------------------------------------------------------------------------------------------------
import requests
record = "CVE-1999-0001"

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

print(cwe,cvss_v,cvss_s,description,product_t,vendor,product_n,product_v)


               



