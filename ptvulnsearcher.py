import sys
import getopt
import requests
import json
import argparse

def search_cve(search_string):
    api_url = "https://as.penterep.com:8443/api/v1/cve/search"
    parameters = {"search": search_string}
    response = requests.get(api_url, params=parameters)
    response_json = response.json()
    
    return json.dumps(response_json, indent=2)

def search(argv):
    search_string = ""
    search_cve = ""
    search_help = "{0} -s <search string> -c <cve>".format(argv[0])
    
    try:
        opts, args = getopt.getopt(argv[1:], "hsc:", ["help", "search=", "cve="])

        for opt, arg in opts:
            if opt in ("-h", "--help"):
                print(search_help)  # print the help message
                sys.exit(2)
            elif opt in ("-s", "--search"):
                search_string = arg
            elif opt in ("-c", "--cve"):
                search_cve = arg

        response = search_cve(search_string)
        sys.exit(2)

    except Exception as e:
        print(e)
        print(search_help)
        sys.exit(2)

parser = argparse.ArgumentParser()
parser.add_argument("-s", "--search" type=string, help="Search keywoards")

if __name__ == "__main__":
    search(sys.argv)
