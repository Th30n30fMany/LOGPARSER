from scapy.all import *
import struct
import ctypes
uint8 = ctypes.c_uint8
uint16 = ctypes.c_uint16
class MALDHeader(ctypes.BigEndianStructure):
	_pack_ = True
	_fields_ = [
		("version", uint8, 3),
		("opcode", uint8, 5),
		("length", uint16),
	]

opcodes = {1: "BEGIN", 2: "TERMINATE", 3: "ACKBEGIN", 5: "BATCH"}

def xor(one, two):
	return bytes(a ^ b for (a, b) in zip(one, two))

pcap = rdpcap("plates.pcapng").filter(lambda x: UDP in x)
print(pcap)

nonce1 = None
nonce2 = None
key = None

for packet in pcap:
	payload = bytes(packet[UDP].payload) # Grab the UDP payload
	hdr = MALDHeader.from_buffer_copy(payload[0:3]) # Parse the header
	print(hdr.version, opcodes[hdr.opcode], "\tLen:", hdr.length)
	
	if hdr.opcode == 1:
		print("Decoding Begin...")
		nonce1 = payload[3:] # Pull Nonce1 out of Begin
		print("NONCE1", nonce1, "Length:", len(nonce1))

	if hdr.opcode == 3:
		print("Decoding AckBegin...")
		nonce2 = payload[3:] # Pull Nonce2 out of AckBegin
		print("NONCE2", nonce2, "Length:", len(nonce2))
		key = xor(nonce1, nonce2) # Calculate the key
		print("KEY", key, "Length:", len(key))
	
	if hdr.opcode == 5:
		print("Decoding LicensePlateBatch...")
		numplates = hdr.length // 16
		print("Entries:", numplates)
		for i in range(numplates): # For each license plate scan in the batch
			offset = 3 + i * 16
			plate = payload[offset:offset+16]
			timing, = struct.unpack('!H', plate[0:2])
			encstate = plate[2:4]
			encplate = plate[4:14]
			discretionary = plate[14:]
			print(timing, "\t",
				xor(encstate, key).decode(),
				xor(encplate, key),
				discretionary
			)