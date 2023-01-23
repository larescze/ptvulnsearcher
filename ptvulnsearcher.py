#!/usr/bin/python3

__version__ = "0.0.1"

from ptlibs import ptjsonlib, ptmisclib
import argparse
import sys
import requests
import json
import datacollector
from api import cve,vendor, vendor_productname, vendor_productname_version, product_name,productname_version


class ptvulnsearcher:
    def __init__(self, args):
        self.ptjsonlib = ptjsonlib.ptjsonlib(args.json)
        self.json_no = self.ptjsonlib.add_json("ptvulnsearcher")
        self.use_json = args.json
        self.args = args

    def run(self):
        if self.args.search or self.args.cve:
            vulns = search_cve(self.args.search, self.args.cve)
            if self.args.json:
                print(vulns)
            else:
                vulns = json.loads(vulns)
                ptmisclib.ptprint_(ptmisclib.out_ifnot(
                    f"Found {len(vulns)} CVE Records", "INFO", self.use_json))
                for vuln in vulns:
                    cve = vuln["cve"]
                    desc = vuln["description"]
                    score = vuln["cvss_score"] if vuln["cvss_score"] else "Not defined"
                    vector = vuln["cvss_string"] if vuln["cvss_string"] else "Not defined"
                    ptmisclib.ptprint_(
                        ptmisclib.out_ifnot(f" ", "", self.use_json))
                    ptmisclib.ptprint_(ptmisclib.out_title_ifnot(
                        f"{cve}", self.use_json))
                    ptmisclib.ptprint_(
                        ptmisclib.out_ifnot(f'\n{ptmisclib.get_colored_text("Description:", color="TITLE")} {desc}', "", self.use_json))
                    ptmisclib.ptprint_(
                        ptmisclib.out_ifnot(f'{ptmisclib.get_colored_text("CVSS Score:", color="TITLE")} {score}', "", self.use_json))
                    ptmisclib.ptprint_(
                        ptmisclib.out_ifnot(f'{ptmisclib.get_colored_text("CVSS Vector:", color="TITLE")} {vector}', "", self.use_json))
            sys.exit(0)
        ptmisclib.ptprint_(ptmisclib.out_if(
            self.ptjsonlib.get_all_json(), "", self.use_json))


def get_help():
    return [
        {"description": [
            "Tool for searching CVE (Common Vulnerabilities and Exposures)"]},
        {"usage": ["ptvulnsearcher <options>"]},
        {"usage_example": [
            "ptvulnsearcher -s Apache v2.2",
        ]},
        {"options": [
            ["-s", "--search", "<search>", "Search keywords"],
            ["-j",  "--json", "",  "Output in JSON format"],
            ["-v",  "--version", "", "Show script version and exit"],
            ["-h", "--help", "", "Show this help message and exit"],
        ]
        }]


def search_cve(search_string, search_cve):
    api_url = "https://as.penterep.com:8443/api/v1/cve/search"
    parameters = {"search": search_string, "cve": search_cve}
    response = requests.get(api_url, params=parameters)
    response_json = response.json()

    return json.dumps(response_json['data'], indent=2)


def parse_args():
    parser = argparse.ArgumentParser(
        add_help=False, usage=f"{SCRIPTNAME} <options>")
    parser.add_argument("-s", "--search", dest="search", choices=['cve','v', 'vp','vpv','p','pv'], 
                        help="Search can be based on: \n-cve -> CVE ID\n-v -> vendor's name\n-vp -> vendor's and product's name\n-vpv -> vendor's and product's name and product's version\n-p -> product's name\n-pv -> product's name and version")
    parser.add_argument("-j", "--json", action="store_true")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-h","--help", action="get_help", type=get_help)
    

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptmisclib.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)

    elif 'cve':
        cve_id = input("Enter CVE ID: ")
        cve(cve_id) #Function call
    elif 'v':
        vendors_name = input("Enter vendor's name: ")
        vendor(vendors_name)#Function call
    elif '-vp':
        vendors_name = input("Enter vendor's name: ")
        products_name = input("Enter product's name: ")
        vendor_productname(vendors_name,products_name)#Function call
    elif '-vpv':
        vendors_name = input("Enter vendor's name: ")
        products_name = input("Enter product's name: ")
        version = input("Enter product's version: ")
        vendor_productname_version(vendors_name,products_name,version)#Function call
    elif '-p':
        products_name = input("Enter product's name: ")
        product_name(products_name)#Function call
    elif '-pv':
        products_name = input("Enter product's name: ")
        version = input("Enter product's version: ")
        productname_version(products_name,version)#Function call


    args = parser.parse_args()
    ptmisclib.print_banner(SCRIPTNAME, __version__, args.json)
    return args


def main():
    global SCRIPTNAME
    SCRIPTNAME = "ptvulnsearcher"
    args = parse_args()
    script = ptvulnsearcher(args)
    script.run()





if __name__ == "__main__":
    main()
