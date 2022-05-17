import sys
import getopt
import requests
import json
import argparse

def search_cve(search_string, search_cve):
    api_url = "https://as.penterep.com:8443/api/v1/cve/search"
    parameters = {"search": search_string, "cve": search_cve}
    response = requests.get(api_url, params=parameters)
    response_json = response.json()
    
    return json.dumps(response_json, indent=2)

def search(args):
    if(args.search):
        print(search_cve(args.search, args.cve))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--search")
    parser.add_argument("-cve", "--cve")

    args = parser.parse_args()

    search(args)
