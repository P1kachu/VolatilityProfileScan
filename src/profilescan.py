import volatility.scan as scan
import volatility.utils as utils
import volatility.commands as commands


class SignatureScanner(scan.BaseScanner):
    checks = []

    def __init__(self, signatures=None):
        self.checks = [("SignatureCheck", {'signatures': signatures})]
        scan.BaseScanner.__init__(self)


class SignatureCheck(scan.ScannerCheck):
    """ Looks for binary signature """
    signature_hashes = []

    def __init__(self, address_space, signatures=None):
        scan.ScannerCheck.__init__(self, address_space)
        if not signatures:
            signatures = []
        self.signatures_hashes = signatures

    def signature_matches(self, signature, dump_chunk):
        magic = int(signature['magic'].encode('hex'), 16)
        mask = int(signature['mask'].encode('hex'), 16)
        chunk = int(dump_chunk.encode('hex'), 16)

        return chunk | mask == magic

    def check(self, offset):
        for signature in self.signature_hashes:
            print("Chunk")
            dump_chunk = self.address_space.read(offset, len(signature['magic']))
            return self.signature_matches(signature, dump_chunk)


class ProfileScan(commands.Command):
    """
    \033[31;1mScan for executables to try to determine the underlying OS\033[0m
    """

    signatures = [{
        'name': "elf",
        'magic': '\x1fELF',
        'offset': 0,
        'mask': '\xff\xff\xff\xff'
    }, {
        'name': 'pe',
        'magic': '\x5a\x40',
        'offset': 0,
        'mask': '\xff\xff'
    }, {
        'name': 'exe',
        'magic': '\x4d\x5a',
        'offset': 0,
        'mask': '\xff\xff'
    }, {
        'name': 'mach-o_32',
        'magic': '\xfe\xed\xfa\xce',
        'offset': 0,
        'mask': '\xff\xff\xff\xff'

    }, {
        'name': 'mach-o_64',
        'magic': '\xfe\xed\xfa\xcf',
        'offset': 0,
        'mask': '\xff\xff\xff\xff'

    }, {
        'name': 'osx_dmg',
        'magic': '\x78\x01\x73\x0d\x62\x62\x60',
        'offset': 0,
        'mask': '\xff\xff\xff\xff\xff\xff\xff'

    }]

    def calculate(self):
        address_space = utils.load_as(self._config, astype='physical')
        scanner = SignatureScanner(self.signatures)
        for offset in scanner.scan(address_space):
            print(offset)

    def render_text(self, outfd, data):
        outfd.write('Hello world!\n')
