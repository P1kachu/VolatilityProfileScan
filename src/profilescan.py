import operator
import volatility.scan as scan
import volatility.utils as utils
import volatility.commands as commands


class SignatureScanner(scan.BaseScanner):
    checks = []

    def __init__(self, signatures=None):
        self.checks = [("SignatureCheck", {'signatures': signatures})]
        scan.BaseScanner.__init__(self)


class SignatureCheck(scan.ScannerCheck):
    """ Looks for binary signatures """
    signature_hashes = []
    PAGE_SIZE = 4096

    def __init__(self, address_space, signatures=None):
        scan.ScannerCheck.__init__(self, address_space)
        if not signatures:
            signatures = []
        self.signature_hashes = signatures

    def check(self, offst):
        """
        Check for each executable format if the byte sequence
        at offst matches its signature
        :param offst: offst to check - multiple of PAGE_SIZE
        :return: boolean
        """

        # Might be a way to do that in superclass
        if offst % self.PAGE_SIZE:
            return False

        for signature in self.signature_hashes:

            # Read sequence of bytes of length equal to the signature's length
            dump_chunk = self.address_space.read(offst, len(signature['magic']))

            # Convert hex strings to int to perform comparison
            magic = int(signature['magic'].encode('hex'), 16)
            mask = int(signature['mask'].encode('hex'), 16)
            chunk = int(dump_chunk.encode('hex'), 16)
            if (chunk | mask) == magic:
                return True

        return False


class ProfileScan(commands.Command):
    """
    Scan for executables to try to determine the underlying OS
    """

    dos_mode_string = 'This program cannot be run in DOS mode'
    signatures = [{
        'formt': "elf",
        'os_id': 'lin',
        'magic': '\x7F\x45\x4C\x46\xff\x01\x01\xff\x00\x00\x00\x00\x00\x00\x00\x00',
        'offst': 0,
        'mask': '\x00\x00\x00\x00\xff\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00'
    }, {
        'formt': 'dos_mode',
        'os_id': 'win',
        'magic': dos_mode_string,
        'offst': 0,
        'mask': len(dos_mode_string) * "\x00",
    }, {
        'formt': 'exe',
        'os_id': 'win',
        'magic': '\x4d\x5a\xff\x00\xff\x00\x00\x00\xff\x00\xff\x00\xff\xff\x00\x00',
        'offst': 0,
        'mask': '\x00\x00\xff\x00\xff\x00\x00\x00\xff\x00\xff\x00\xff\xff\x00\x00',
    }, {
        'formt': 'mach-o_32',
        'os_id': 'mac',
        'magic': '\xfe\xed\xfa\xce',
        'offst': 0,
        'mask': '\x00\x00\x00\x00'

    }, {
        'formt': 'mach-o_64',
        'os_id': 'mac',
        'magic': '\xfe\xed\xfa\xcf',
        'offst': 0,
        'mask': '\x00\x00\x00\x00'

    }, {
        'formt': 'mach-o_32-rev',
        'os_id': 'mac',
        'magic': '\xce\xfa\xed\xfe',
        'offst': 0,
        'mask': '\x00\x00\x00\x00'

    }, {
        'formt': 'mach-o_64-rev',
        'os_id': 'mac',
        'magic': '\xcf\xfa\xed\xfe',
        'offst': 0,
        'mask': '\x00\x00\x00\x00'

    }, {
        'formt': 'mac_dmg',
        'os_id': 'mac',
        'magic': '\x78\x01\x73\x0d\x62\x62\x60',
        'offst': 0,
        'mask': '\x00\x00\x00\x00\x00\x00\x00'

    }]

    occurences = {
        'win': 0,
        'mac': 0,
        'lin': 0,
    }

    def calculate(self):

        # Number of executables to find before trying to stop
        MIN_LIMIT = 15

        # Min percentage threshold for an format to reach before
        # being interesting
        THRESHOLD = 90

        address_space = utils.load_as(self._config, astype='physical')

        scanner = SignatureScanner(self.signatures)

        for offst in scanner.scan(address_space):
            # Read the two first bytes at the offst that triggered
            # Might be a simpler way to do that (return format instead of offst ?)
            magic = address_space.zread(offst, 0x2)

            # Compare to each signature's first two bytes,
            # and increment the right id
            for sig in self.signatures:
                if sig['magic'][:2] == magic:
                    self.occurences[sig['os_id']] += 1
                    if self._config.get_value('verbose') != 0:
                        print("[ ] DEBUG: {0} found at offst {1}".format(sig['formt'], hex(offst)))

                    # If minimum limit was reached, check if it is > THRESHOLD
                    if max([self.occurences[item] for item in self.occurences]) > MIN_LIMIT:
                        for occ in self.occurences:
                            nb_of_occurences = self.occurences[occ]
                            percentage = nb_of_occurences / sum([self.occurences[item] for item in self.occurences]) * 100
                            if nb_of_occurences > MIN_LIMIT and percentage > THRESHOLD:
                                hightest_id = sorted(self.occurences.items(), key=operator.itemgetter(1), reverse=True)[0][0]
                                return hightest_id, percentage

    def render_text(self, outfd, data):
        highest, percentage = data
        probable_os = 'Unknown'
        if highest == 'lin':
            probable_os = 'Linux'
        if highest == 'win':
            probable_os = 'Windows'
        if highest == 'mac':
            probable_os = 'OSX'
        outfd.write("Found OS: {0} ({1}% match)\n".format(probable_os, percentage))
