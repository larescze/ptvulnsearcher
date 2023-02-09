#!/usr/bin/python3

__version__ = "0.0.1"

from ptlibs import ptjsonlib, ptmisclib
import argparse
import sys
import requests
import json
from api import app, cve, vendor, vendor_productname, vendor_productname_version, product_name, productname_version

class ptvulnsearcher:
    def __init__(self, args):
        self.ptjsonlib = ptjsonlib.ptjsonlib(args.json)
        self.json_no = self.ptjsonlib.add_json("ptvulnsearcher")
        self.use_json = args.json
        self.args = args

    def run(self): 
        if self.args.cve: #POKRACOVAT
            vulns = cve(self.args.cve)
            if self.args.json:
                print(vulns)
            else:
                vulns = json.loads(vulns)
                ptmisclib.ptprint_(ptmisclib.out_ifnot(
                    f"Found {len(vulns)} CVE Records", "INFO", self.use_json))
                for vuln in vulns:
                    cve = vuln["cve_id"]
                    cwe = vuln["cwe_id"]
                    cvss_vector = vulns["cvss_vector"]
                    cvss_score = vulns["cvss_score"]
                    desc = vuln["description"]
                    vendor = vulns["vendor"]
                    product_type = ["product_type"]
                    product_name = ["product_name"]
                    version = vulns["version"]
                    ptmisclib.ptprint_(
                        ptmisclib.out_ifnot(f" ", "", self.use_json))
                    ptmisclib.ptprint_(ptmisclib.out_title_ifnot(
                        f"{cve}", self.use_json))
                    ptmisclib.ptprint_(
                        ptmisclib.out_ifnot(f'\n{ptmisclib.get_colored_text("Cve ID:", color="TITLE")} {cve}', "", self.use_json))
                    ptmisclib.ptprint_(
                        ptmisclib.out_ifnot(f'\n{ptmisclib.get_colored_text("Cwe ID:", color="TITLE")} {cwe}', "", self.use_json))
                    ptmisclib.ptprint_(
                        ptmisclib.out_ifnot(f'\n{ptmisclib.get_colored_text("CVSS Vector:", color="TITLE")} {cvss_vector}', "", self.use_json))
                    ptmisclib.ptprint_(
                        ptmisclib.out_ifnot(f'\n{ptmisclib.get_colored_text("CVSS Score:", color="TITLE")} {cvss_score}', "", self.use_json))
                    ptmisclib.ptprint_(
                        ptmisclib.out_ifnot(f'{ptmisclib.get_colored_text("Description:", color="TITLE")} {desc}', "", self.use_json))
                    ptmisclib.ptprint_(
                        ptmisclib.out_ifnot(f'{ptmisclib.get_colored_text("Vendor:", color="TITLE")} {vendor}', "", self.use_json))
                    ptmisclib.ptprint_(
                        ptmisclib.out_ifnot(f'{ptmisclib.get_colored_text("Product name:", color="TITLE")} {product_name}', "", self.use_json))
                    ptmisclib.ptprint_(
                        ptmisclib.out_ifnot(f'{ptmisclib.get_colored_text("Product type:", color="TITLE")} {product_type}', "", self.use_json))
                    ptmisclib.ptprint_(
                        ptmisclib.out_ifnot(f'{ptmisclib.get_colored_text("Version:", color="TITLE")} {version}', "", self.use_json))
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
            ["-c","--cve", "Search based on CVE ID"],
            ["-vn","--vendor_name", "Search based on vendor name"],
            ["-pn","--product_name", "Search based on product name"],
            ["-pv","--product_version", "Search based on product version"],
            ["-j",  "--json","Output in JSON format"],
            ["-V",  "--version","Show script version and exit"],
            ["-h", "--help","Show this help message and exit"],
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
    parser.add_argument("-cve","--cve")
    parser.add_argument("-vn","--vendor_name")
    parser.add_argument("-pn","--product_name")
    parser.add_argument("-pv","--product_version")
    parser.add_argument("-j", "--json", action="store_true")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    #parser.add_argument("-h","--help", action="get_help", type=get_help)

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptmisclib.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)

    args = parser.parse_args()

    if args.cve:
        cve(args.cve)
    elif args.vendor_name:
        print(vendor(args.vendor_name))
    elif args.vendor_name and args.product_name:
        print(vendor_productname(args.vendor_name, args.product_name))
    elif args.vendor_name and args.product_name and args.product_version:
        vendor_productname_version(args.vendor_name,args.product_name,args.product_version)
    elif args.product_name:
        product_name(args.product_name)
    elif args.product_name and args.product_version:
        productname_version(args.product_name,args.product_version)
    else:
        sys.exit("Invalid input")

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
