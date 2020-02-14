import struct

from scapy.data import ETHER_TYPES


class Ether:
    name = "Ethernet"

    def __init__(self, src: str, dst: str, type: ETHER_TYPES, payload=None):
        self.src = src
        self.dst = dst
        self.type = type
        self.payload = payload

    def hashret(self):
        return struct.pack("H", self.type) + self.payload.hashret()

    def answers(self, other):
        if isinstance(other, Ether):
            if self.type == other.type:
                return self.payload.answers(other.payload)
        return 0

    def mysummary(self):
        return '{} > {} ({})'.format(self.src, self.dst, self.type)