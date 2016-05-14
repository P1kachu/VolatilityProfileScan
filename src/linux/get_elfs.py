import operator
import volatility.scan as scan
import volatility.utils as utils
import volatility.commands as commands


class ElfScanner(scan.BaseScanner):
    checks = []

    def __init__(self, signatures=None):
        self.checks = [("ElfCheck", {'signatures': signatures})]
        scan.BaseScanner.__init__(self)


class ElfCheck(scan.ScannerCheck):
    """ Looks for binary signatures """
    signature_hashes = []
    PAGE_SIZE = 4096
    elf = {
        'formt': "elf",
        'os_id': 'lin',
        'magic': '\x7F\x45\x4C\x46\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00',
        'offst': 0,
        'mask': '\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00'
    }

    def __init__(self, address_space, signatures=None):
        scan.ScannerCheck.__init__(self, address_space)

    def check(self, offst):
        """
           Check for each executable format if the byte sequence
           at offst matches its signature
           :param offst: offst to check - multiple of PAGE_SIZE
           :return: boolean
        """  # Might be a way to do that in superclass
        if offst % self.PAGE_SIZE:
            return False

        # Read sequence of bytes of length equal to the signature's length
        dump_chunk = self.address_space.read(offst, len(self.elf['magic']))

        # Convert hex strings to int to perform comparison
        magic = int(self.elf['magic'].encode('hex'), 16)
        mask = int(self.elf['mask'].encode('hex'), 16)
        chunk = int(dump_chunk.encode('hex'), 16)
        if (chunk | mask) == magic:
            return True

        return False


class GetElfs(commands.Command):
    """
       Scan for executables to try to determine the underlying OS
    """

    bit_format = {
        0x01: "32-bit",
        0x02: "64-bit"
    }

    endianess = {
        0x01: "LSB",
        0x02: "MSB"
    }

    abi = {
        0x00: "System V",
        0x01: "HP-UX",
        0x02: "NetBSD",
        0x03: "Linux",
        0x06: "Solaris",
        0x07: "AIX",
        0x08: "IRIX",
        0x09: "FreeBSD",
        0x0C: "OpenBSD",
        0x0D: "OpenVMS",
        0x0E: "NSK operating system",
        0x0F: "AROS",
        0x10: "Fenix OS",
        0x11: "CloudABI",
    }

    elf_type = {
        0x01: "relocatable",
        0x02: "executable",
        0x03: "shared object",
        0x04: "core"
    }

    isa = {
        0x00: "No specific instruction set",
        0x02: "SPARC",
        0x03: "x86",
        0x08: "MIPS",
        0x14: "PowerPC",
        0x28: "ARM",
        0x2A: "SuperH",
        0x32: "IA-64",
        0x3E: "x86-64",
        0xB7: "AArch64",
    }

    def calculate(self):
        address_space = utils.load_as(self._config, astype='physical')

        scanner = ElfScanner()

        i = 0
        for offst in scanner.scan(address_space):
            i += 1
            if i == 0x10:
                return
            magic = address_space.zread(offst, 0x20)
            elf_bit_fmt = self.bit_format[int(magic[0x04].encode('hex'), 16)]
            elf_endianess = self.endianess[int(magic[0x05].encode('hex'), 16)]
            elf_abi = self.abi[int(magic[0x07].encode('hex'), 16)]
            elf_elf_type = self.elf_type[int(magic[0x10].encode('hex'), 16)]
            elf_isa = self.isa[int(magic[0x12].encode('hex'), 16)]

            if self._config.get_value('verbose') != 0:
                s = "[ ] DEBUG: found at offst {0}: ELF {1} {2} {3}, {4}, {5}"
                print(s.format(hex(offst), elf_bit_fmt, elf_endianess, elf_elf_type, elf_abi, elf_isa))

    def render_text(self, outfd, data):
        probable_os = 'Unknown'
        outfd.write("Found OS: {0}\n".format(probable_os))
