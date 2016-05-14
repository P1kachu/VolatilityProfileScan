#!/usr/bin/python2
import os
from VolatilityProfileDiscovery import ProfileExplorer

try:
    dump_dir = os.environ['VPD_DIR']
except:
    raise EnvironmentError("$VPD_DIR not set.")

# From https://blog.lse.epita.fr/articles/59-ebctf-2013-for100.html
explorer = ProfileExplorer("{0}ubuntudump".format(dump_dir))
explorer.discover()
