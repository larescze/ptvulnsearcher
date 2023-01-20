"""import requests


request = requests.get("https://cve.circl.lu/api/cve/CVE-1999-0159")
response = request.json()
product_v = response["vulnerable_product"][-1].split(":")[5].split('\\')[0]
print(product_v)"""


#-----------------------------------------------------------------------------------------------------
import os

i = input("Input: ")
potentially_deangerous = ['<','>','\'','\"',"AND","OR","SELECT","UNION","DROP","ALTER","FROM"]
for content1 in i.split(' '):
    for content2 in potentially_deangerous:
        if (content1 == content2):
            os.abort(404)


#Alter this into a function and implement it into to a main code 'api.py'

