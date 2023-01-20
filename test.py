import requests


request = requests.get("https://cve.circl.lu/api/cve/CVE-1999-0159")
response = request.json()
product_v = response["vulnerable_product"][-1].split(":")[5].split('\\')[0]
print(product_v)