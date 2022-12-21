#!/usr/bin/python3
import argparse
import api

parser = argparse.ArgumentParser()
parser.add_argument("vendor")


args = parser.parse_args()
api.vendor(args.vendor)