#!/usr/bin/python2
import sys
from VolatilityProfileDiscovery import ProfileDiscovery

def print_banner():
    banner = "Volatility Profile Discovery tool"
    print(banner)
    print("-" * len(banner))
    print("")

def print_usage_and_exit():
    print("USAGE: {0} DUMP".format(sys.argv[0]))
    exit(0)

if __name__ in "__main__":
    print_banner()

    if len(sys.argv) < 2:
        print_usage_and_exit()

    vpd = ProfileDiscovery(sys.argv[1])
    vpd.discover()

