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

    def check(self, offset):
        """
        Check for each executable format if the byte sequence
        at offset matches its signature
        :param offset: offset to check - multiple of PAGE_SIZE
        :return: boolean
        """

        # Might be a way to do that in superclass
        if offset % self.PAGE_SIZE:
            return False

        for signature in self.signature_hashes:

            # Read sequence of bytes of length equal to the signature's length
            dump_chunk = self.address_space.read(offset, len(signature['magic']))

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
        'name': "elf",
        'id': 'lin',
        'magic': '\x7F\x45\x4C\x46\xff\x01\x01\xff\x00\x00\x00\x00\x00\x00\x00\x00',
        'offset': 0,
        'mask': '\x00\x00\x00\x00\xff\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00'
    }, {
        'name': 'dos_mode',
        'id': 'win',
        'magic': dos_mode_string,
        'offset': 0,
        'mask': len(dos_mode_string) * "\x00",
        # }, {
        #     'name': 'pe',
        #     'id': 'win',
        #     'magic': '\x5a\x40',
        #     'offset': 0,
        #     'mask': '\x00\x00'
    }, {
        'name': 'exe',
        'id': 'win',
        'magic': '\x4d\x5a\xff\x00\xff\x00\x00\x00\xff\x00\xff\x00\xff\xff\x00\x00',
        'offset': 0,
        'mask': '\x00\x00\xff\x00\xff\x00\x00\x00\xff\x00\xff\x00\xff\xff\x00\x00',
    }, {
        'name': 'mach-o_32',
        'id': 'mac',
        'magic': '\xfe\xed\xfa\xce',
        'offset': 0,
        'mask': '\x00\x00\x00\x00'

    }, {
        'name': 'mach-o_64',
        'id': 'mac',
        'magic': '\xfe\xed\xfa\xcf',
        'offset': 0,
        'mask': '\x00\x00\x00\x00'

    }, {
        'name': 'mach-o_32-rev',
        'id': 'mac',
        'magic': '\xce\xfa\xed\xfe',
        'offset': 0,
        'mask': '\x00\x00\x00\x00'

    }, {
        'name': 'mach-o_64-rev',
        'id': 'mac',
        'magic': '\xcf\xfa\xed\xfe',
        'offset': 0,
        'mask': '\x00\x00\x00\x00'

    }, {
        'name': 'mac_dmg',
        'id': 'mac',
        'magic': '\x78\x01\x73\x0d\x62\x62\x60',
        'offset': 0,
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

        for offset in scanner.scan(address_space):
            # Read the two first bytes at the offset that triggered
            # Might be a simpler way to do that (return format instead of offset ?)
            magic = address_space.zread(offset, 0x2)

            # Compare to each signature's first two bytes,
            # and increment the right id
            for sig in self.signatures:
                if sig['magic'][:2] == magic:
                    self.occurences[sig['id']] += 1
                    if self._config.get_value('verbose') != 0:
                        print("[ ] DEBUG: {0} found at offset {1}".format(sig['name'], hex(offset)))

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
