#!/usr/bin/python2
import os
from VolatilityProfileDiscovery import ProfileDiscovery

try:
    dump_dir = os.environ['VPD_DIR']
except:
    raise EnvironmentError("$VPD_DIR not set.")

# From https://drive.google.com/file/d/0B_zt1fDAjfM_Zy1YZFhkQkg4NTg/view
explorer = ProfileDiscovery("{0}debiandump".format(dump_dir))
explorer.discover()
