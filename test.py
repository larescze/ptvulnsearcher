#!/usr/bin/python3
import argparse


parser = argparse.ArgumentParser()
parser.add_argument('--values', type=str, nargs=2)
args = parser.parse_args()
print(args.values[0])


#metavar = different names for optional arguments -> 'Positional argument N' in case above
"""action = triggers different action based on value assigned to it
    -store
    store true/false
    store_const
    append
    append_const
    version
    """