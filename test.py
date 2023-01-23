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
import argparse
parser = argparse.ArgumentParser()
parser.add_argument("echo", help="enter whatever you want")
args = parser.parse_args()
print(args.echo)


               



