#!/usr/bin/python2

"""
Volatility Profile Discovery Tool

@author:  Stanislas 'P1kachu' Lejay
@contact: p1kachu@lse.epita.fr
"""

import re
import sys
import os.path
import operator
import volatility.conf as conf
import volatility.debug as debug
import volatility.registry as registry
import volatility.commands as commands
import volatility.addrspace as addrspace
import volatility.plugins.imageinfo as imageinfo


# OS NAMES
class ProfileExplorer:
    """
    Used to guess the operating system lying in a dump in order to choose a
    profile for Volatility
    Based on simple occurence counting
    """

    os_names = {
        'linux': 0,
        'ubuntu': 0,
        'debian': 0,
        'windows': 0,
        'osx': 0,
        'centos': 0,
        'fedora': 0,
        'opensuse': 0,
        'redhat': 0
        }

    debian_distributions = {
        'hamm': 0,
        'slink': 0,
        'potato': 0,
        'woody': 0,
        'sarge': 0,
        'etch': 0,
        'lenny': 0,
        'squeeze': 0,
        'wheezy': 0,
        'jessie': 0,
        'stretch': 0
        }

    cpu_flavor = {
            'x64': 0,
            'x86_64': 0,
            'x86': 0,
            }

    dump = ''

    def __init__(self, dump):
        dump = os.path.expanduser(dump)
        if not os.path.isfile(dump):
            raise IOError("File not found: {0}".format(dump))
        self.dump = dump

    @staticmethod
    def read_file(f, chunk_size=4096):
        """
        Reads a file chunk by chunk
        """
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk


    def mini_grep(self, elements):
        """
        Tries to determine the operating system from the file by counting the
        occurences of each os_names strings

        Tries to be plateform independant
        """
        for elt in elements:
            elements[elt] = 0

        with open(self.dump, "rb") as f:
            for chunk in self.read_file(f):
                for elt in elements:
                    elements[elt] += chunk.count(str.encode(elt))

        # Order the OSes by number of occurences, decreasing order.
        s = sorted(elements.items(), key=operator.itemgetter(1), reverse=True)

        # Returns the OS with the higher number of occurences
        if elements[s[0][0]] > 0:
            return s[0][0]
        return "Unknown"


    def handle_windows(self, probable_os):
        """
        Calls Volatility's API to display the correct Windows informations
        """
        print("[+] Probable OS: {0}".format(probable_os))
        print("[ ] Launching volatility imageinfo - Please wait...")
        registry.PluginImporter()
        config = conf.ConfObject()
        registry.register_global_options(config, commands.Command)
        registry.register_global_options(config, addrspace.BaseAddressSpace)
        config.LOCATION = 'file://{0}'.format(self.dump)
        infos = imageinfo.ImageInfo(config)
        data = infos.execute()


    def handle_osx(self, probable_os):
        # TODO: Based on Votality's mac_get_profile plugin
        print("[+] Probable OS: {0}".format(probable_os))
        print("[ ] Launching volatility mac_get_profile - Please wait...")
        raise NotImplementedError("OSX Handling missing")



    def discover(self):
        """
        Main operations
        """

        # Guess the OS
        probable_os = self.mini_grep(self.os_names)

        if probable_os == "Unknown":
            print("[-] Operating system not found")
            return


        # Windows dump
        if probable_os == "windows":
            self.handle_windows(probable_os)
            return

        # OSX dump
        if probable_os == 'osx':
            self.handle_osx(probable_os)
            return

        ####### EXPERIMENTAL ########
        version = "Unknown"
        probable_distrib = "Unknown"

        # Tries to guess the unix version
        # AKA 'vmlinuz-MAJOR.MINOR(s)-rev
        try:
            flavor = [re.findall(r'vmlinuz-\d+[\.\d+]*-\d+', line)
                    for line in open(self.dump)]
            filtered = [f for f in flavor if f != []]
            version = filtered[0][0]
        except:
            version = "Unknown"

        if probable_os == "debian":
            # Uses the same method as for the OS finding
            probable_distrib = self.mini_grep(self.debian_distributions)

        print("[+] Probable OS            : {0}".format(probable_os))
        print("[+] Probable Distribution  : {0}".format(probable_distrib))
        print("[+] Probable Kernel version: {0}".format(version))





# -----------------------------------------------------------------------------



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

    vpd = ProfileExplorer(sys.argv[1])
    vpd.discover()

