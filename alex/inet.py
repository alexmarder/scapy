import socket
import struct

import scapy.layers.inet6
from scapy.compat import chb, raw
from scapy.config import conf
from scapy.utils import whois, checksum, strxor


class IPTools:
    """Add more powers to a class with an "src" attribute."""
    def __init__(self, src, ttl=64):
        self.src = src
        self.ttl = ttl

    def whois(self):
        """whois the source and print the output"""
        print(whois(self.src).decode("utf8", "ignore"))

    def _ttl(self):
        """Returns ttl or hlim, depending on the IP version"""
        return self.hlim if isinstance(self, scapy.layers.inet6.IPv6) else self.ttl  # noqa: E501

    def ottl(self):
        t = sorted([32, 64, 128, 255] + [self._ttl()])
        return t[t.index(self._ttl()) + 1]

    def hops(self):
        return self.ottl() - self._ttl()

class IP(IPTools):
    name = 'IP'

    def __init__(self, version=4, ihl=None, tos=0, len=None, id=1, flags=0, frag=0, ttl=64, proto=0, chksum=None, src=None, dst='127.0.0.1', options=None, payload=None):
        src = src if src is not None else dst
        super().__init__(src, ttl=ttl)
        self.version = version
        self.ihl = ihl
        self.tos = tos
        self.len = len
        self.id = id
        self.flags = flags
        self.frag = frag
        self.proto = proto
        self.chksum = chksum
        self.dst = dst
        self.options = options if options is not None else []
        self.payload = payload

    def post_build(self, p, pay):
        ihl = self.ihl
        p += b"\0" * ((-len(p)) % 4)  # pad IP options if needed
        if ihl is None:
            ihl = len(p) // 4
            p = chb(((self.version & 0xf) << 4) | ihl & 0x0f) + p[1:]
        if self.len is None:
            tmp_len = len(p) + len(pay)
            p = p[:2] + struct.pack("!H", tmp_len) + p[4:]
        if self.chksum is None:
            ck = checksum(p)
            p = p[:10] + chb(ck >> 8) + chb(ck & 0xff) + p[12:]
        return p + pay

    def extract_padding(self, s):
        tmp_len = self.len - (self.ihl << 2)
        if tmp_len < 0:
            return s, b""
        return s[:tmp_len], s[tmp_len:]

    def route(self):
        dst = self.dst
        if conf.route is None:
            # unused import, only to initialize conf.route
            import scapy.route  # noqa: F401
        return conf.route.route(dst)

    def hashret(self):
        if (self.proto == socket.IPPROTO_ICMP) and (isinstance(self.payload, ICMP)) and (self.payload.type in [3, 4, 5, 11, 12]):
            return self.payload.payload.hashret()
        if not conf.checkIPinIP and self.proto in [4, 41]:  # IP, IPv6
            return self.payload.hashret()
        if self.dst == "224.0.0.251":  # mDNS
            return struct.pack("B", self.proto) + self.payload.hashret()
        if conf.checkIPsrc and conf.checkIPaddr:
            return strxor(socket.inet_pton(socket.AF_INET, self.src), socket.inet_pton(socket.AF_INET, self.dst)) + struct.pack("B", self.proto) + self.payload.hashret()
        return struct.pack("B", self.proto) + self.payload.hashret()

    def answers(self, other):
        if not conf.checkIPinIP:  # skip IP in IP and IPv6 in IP
            if self.proto in [4, 41]:
                return self.payload.answers(other)
            if isinstance(other, IP) and other.proto in [4, 41]:
                return self.answers(other.payload)
            if conf.ipv6_enabled \
               and isinstance(other, scapy.layers.inet6.IPv6) \
               and other.nh in [4, 41]:
                return self.answers(other.payload)
        if not isinstance(other, IP):
            return 0
        if conf.checkIPaddr:
            if other.dst == "224.0.0.251" and self.dst == "224.0.0.251":  # mDNS  # noqa: E501
                return self.payload.answers(other.payload)
            elif (self.dst != other.src):
                return 0
        if ((self.proto == socket.IPPROTO_ICMP) and
            (isinstance(self.payload, ICMP)) and
                (self.payload.type in [3, 4, 5, 11, 12])):
            # ICMP error message
            return self.payload.payload.answers(other)

        else:
            if ((conf.checkIPaddr and (self.src != other.dst)) or
                    (self.proto != other.proto)):
                return 0
            return self.payload.answers(other.payload)

    def mysummary(self):
        s = '{} > {} {}'.format(self.src, self.dst, self.proto)
        if self.frag:
            s += " frag:{}".format(self.frag)
        return s

    def fragment(self, fragsize=1480):
        """Fragment IP datagrams"""
        fragsize = (fragsize + 7) // 8 * 8
        lst = []
        fnb = 0
        fl = self
        while fl.underlayer is not None:
            fnb += 1
            fl = fl.underlayer

        for p in fl:
            s = raw(p[fnb].payload)
            nb = (len(s) + fragsize - 1) // fragsize
            for i in range(nb):
                q = p.copy()
                del(q[fnb].payload)
                del(q[fnb].chksum)
                del(q[fnb].len)
                if i != nb - 1:
                    q[fnb].flags |= 1
                q[fnb].frag += i * fragsize // 8
                r = conf.raw_layer(load=s[i * fragsize:(i + 1) * fragsize])
                r.overload_fields = p[fnb].payload.overload_fields.copy()
                q.add_payload(r)
                lst.append(q)
        return lst

class ICMP:
    name = 'ICMP'

    def __init__(self, type=8, code=0, chksum=None, id=0, seq=0, ts_ori=None, ts_rx=None, ts_tx=None, gw='0.0.0.0', ptr=0, reserved=0, length=0, addr_mask='0.0.0.0', nexthopmtu=0, unused=0, payload=None):
        self.type = type
        self.code = code
        self.chksum = chksum
        self.id = id
        self.seq = seq
        self.ts_ori = ts_ori
        self.ts_rx = ts_rx
        self.ts_tx = ts_tx
        self.gw = gw
        self.ptr = ptr
        self.reserved = reserved
        self.length = length
        self.addr_mask = addr_mask
        self.nexthopmtu = nexthopmtu
        self.unused = unused
        self.payload = payload

    def post_build(self, p, pay):
        p += pay
        if self.chksum is None:
            ck = checksum(p)
            p = p[:2] + chb(ck >> 8) + chb(ck & 0xff) + p[4:]
        return p

    def hashret(self):
        if self.type in [0, 8, 13, 14, 15, 16, 17, 18, 33, 34, 35, 36, 37, 38]:
            return struct.pack("HH", self.id, self.seq) + self.payload.hashret()  # noqa: E501
        return self.payload.hashret()

    def answers(self, other):
        if not isinstance(other, ICMP):
            return 0
        if ((other.type, self.type) in [(8, 0), (13, 14), (15, 16), (17, 18), (33, 34), (35, 36), (37, 38)] and  # noqa: E501
            self.id == other.id and
                self.seq == other.seq):
            return 1
        return 0

    def guess_payload_class(self, payload):
        if self.type in [3, 4, 5, 11, 12]:
            return IPerror
        else:
            return None

    def mysummary(self):
        if isinstance(self.underlayer, IP):
            return self.underlayer.sprintf("ICMP %IP.src% > %IP.dst% %ICMP.type% %ICMP.code%")  # noqa: E501
        else:
            return self.sprintf("ICMP %ICMP.type% %ICMP.code%")

class IPerror(IP):
    name = "IP in ICMP"

    def answers(self, other):
        if not isinstance(other, IP):
            return 0

        # Check if IP addresses match
        test_IPsrc = not conf.checkIPsrc or self.src == other.src
        test_IPdst = self.dst == other.dst

        # Check if IP ids match
        test_IPid = not conf.checkIPID or self.id == other.id
        test_IPid |= conf.checkIPID and self.id == socket.htons(other.id)

        # Check if IP protocols match
        test_IPproto = self.proto == other.proto

        if not (test_IPsrc and test_IPdst and test_IPid and test_IPproto):
            return 0

        return self.payload.answers(other.payload)

class ICMPerror(ICMP):
    name = "ICMP in ICMP"

    def answers(self, other):
        if not isinstance(other, ICMP):
            return 0
        if not ((self.type == other.type) and
                (self.code == other.code)):
            return 0
        if self.code in [0, 8, 13, 14, 17, 18]:
            if (self.id == other.id and
                    self.seq == other.seq):
                return 1
            else:
                return 0
        else:
            return 1
