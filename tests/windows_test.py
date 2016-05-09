#!/usr/bin/python2
import os
from VolatilityProfileDiscovery import ProfileExplorer

try:
    dump_dir = os.environ['VPD_DIR']
except:
    raise EnvironmentError("$VPD_DIR not set.")

# From https://w00tsec.blogspot.fr/2014/11/9447-2014-ctf-write-up-coor-coor.html
explorer = ProfileExplorer("{0}windump".format(dump_dir))
explorer.discover()
