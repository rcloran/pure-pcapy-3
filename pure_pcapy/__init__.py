# -*- coding: utf-8 -*-
""" pcapy clone in pure python """

import struct

class PcapError(Exception): pass

def fixup_identical_short(x): return x
def fixup_identical_long(x): return x
def fixup_swapped_short(x):
	return ((x&0xff) << 8) | ((x&0xff00) >> 8)
def fixup_swapped_long(x):
	bottom = fixup_swapped_short(x & 0xffff)
	top = fixup_swapped_short((x >> 16) & 0xffff)
	return ((bottom << 16) & 0xffff0000) | top

fixup_sets = {
		0xa1b2c3d4: (fixup_identical_short, fixup_identical_long),
		0xd4c3b2a1: (fixup_swapped_short, fixup_swapped_long),
		}

def open_offline(filename):
	if filename == "-":
		import sys
		source = sys.stdin
	else:
		try:
			source = open(filename, "rb")
		except Exception, e:
			raise PcapError("file access problem", e)
	
	return Reader(source)

def open_live(device, snaplen, promisc, to_ms):
	raise NotImplementedError("This function is only available in pcapy")

def lookupdev():
	raise NotImplementedError("This function is only available in pcapy")

def findalldevs():
	raise NotImplementedError("This function is only available in pcapy")

def compile(linktype, snaplen, filter, optimize, netmask):
	raise NotImplementedError("not implemented yet")

class Reader(object):
	GLOBAL_HEADER_LEN = 24
	PACKET_HEADER_LEN = 16

	def __init__(self, source):
		self.source = source
		header = self.source.read(self.GLOBAL_HEADER_LEN)
		if len(header) < self.GLOBAL_HEADER_LEN:
			raise PcapError("truncated dump file; tried to read %i file header bytes, only got %i" % (self.GLOBAL_HEADER_LEN, len(header)))
		
		hdr_values = struct.unpack("IHHIIII", header)
		if hdr_values[0] in fixup_sets:
			self.fixup_short, self.fixup_long = fixup_sets[hdr_values[0]]
		else:
			raise PcapError("bad dump file format")

		self.version_major, self.version_minor = [self.fixup_short(x) for x in hdr_values[1:3]]
		self.thiszone, self.sigfigs, self.snaplen, self.network = [self.fixup_long(x) for x in hdr_values[3:]]

		self.last_good_position = self.GLOBAL_HEADER_LEN

	def __loop_and_count(self, maxcant, callback):
		i = 0
		while True:
			if i >= maxcant and maxcant > -1:
				break

			hdr, data = self.next()
			if hdr is None:
				break
			else:
				callback(hdr, data)

			i+=1

		return i

	def dispatch(self, maxcant, callback):
		i = self.__loop_and_count(maxcant, callback)

		if maxcant > -1:
			return i
		else:
			return 0

	def loop(self, maxcant, callback):
		self.__loop_and_count(maxcant, callback)
		return None

	def next(self):
		header = self.source.read(self.PACKET_HEADER_LEN)
		if len(header) == 0:
			return (None, '')
		if len(header) < self.PACKET_HEADER_LEN:
			raise PcapError("truncated dump file; tried to read %i header bytes, only got %i" % (self.PACKET_HEADER_LEN, len(header)))
		hdr_values = struct.unpack("IIII", header)
		ts_sec, ts_usec, incl_len, orig_len = [self.fixup_long(x) for x in hdr_values]
		
		data = self.source.read(incl_len)
		if len(data) < incl_len:
			raise PcapError("truncated dump file; tried to read %i captured bytes, only got %i" % (incl_len, len(data)))

		pkthdr = Pkthdr(ts_sec, ts_usec, incl_len, orig_len)
		return (pkthdr, data)

	def getnet(self):
		raise NotImplementedError("This function is only available in pcapy")

	def getmask(self):
		raise NotImplementedError("This function is only available in pcapy")

	def datalink(self):
		return self.network

	def getnonblock(self):
		return 0

	def setnonblock(self, state):
		""" this has no effect on savefiles, so is not implemented in pure-pcapy """
		pass

class Dumper(object):
	def __init__(self):
		pass

	def dump(self, header, data):
		pass

class Pkthdr(object):
	def __init__(self, ts_sec, ts_usec, incl_len, orig_len):
		self.ts = (ts_sec, ts_usec)
		self.incl_len = incl_len
		self.orig_len = orig_len

	def getts(self):
		return self.ts

	def getcaplen(self):
		return self.incl_len

	def getlen(self):
		return self.orig_len

class Bpf(object):
	def __init__(self):
		raise NotImplementedError("not implemented yet")

	def filter(self, packet):
		raise NotImplementedError("not implemented yet")

