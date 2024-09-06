import sys
import random
import struct
import time
import binascii
import hashlib

tlv_types = {
    "SignedBlock": 0x14,
    "DeviceLicenseExpirationTime": 0x1f,
    "PollingTime": 0xd3,
    "LicenseExpirationTime": 0x20,
    "ClepSignState": 0x12d,
    "LicenseDeviceId": 0xd2,
    "UnkBlock1": 0xd1,
    "LicenseId": 0xcb,
    "HardwareId": 0xd0,
    "UnkBlock2": 0xcf,
    "UplinkKeyId": 0x18,
    "UnkBlock3": 0x0,
    "UnkBlock4": 0x12e,
    "UnkBlock5": 0xd5,
    "PackageFullName": 0xce,
    "LicenseInformation": 0xc9,
    "PackedContentKeys": 0xca,
    "EncryptedDeviceKey": 0x1,
    "DeviceLicenseDeviceId": 0x2,
    "LicenseEntryIds": 0xcd,
    "LicensePolicies": 0xd4,
    "KeyholderPublicSigningKey": 0xdc,
    "KeyholderPolicies": 0xdd,
    "KeyholderKeyLicenseId": 0xde,
    "SignatureBlock": 0xcc,
};

def encode_tlvblock(type, data):
    return struct.pack("<II", tlv_types[type], len(data)) + data

extradata = None

lic_file = sys.argv[1]
new_pfn = sys.argv[2].lower()
out_lic = sys.argv[3]

if len(sys.argv) >= 5:
    extra_file = sys.argv[4]
    
    with open(extra_file, "rb") as f:
        extradata = f.read()

with open(lic_file, "rb") as f:
    data = f.read()

data += encode_tlvblock("PackageFullName", new_pfn.encode("utf-16-le") + b"\x00\x00")

basic_pol = 0x0a
if "addon" in new_pfn:
    basic_pol = 0x00

lic_info = struct.pack("<HHIBB", 5, 1, int(time.time()), basic_pol, 1)
data += encode_tlvblock("LicenseInformation", lic_info)
data += encode_tlvblock("LicenseId", random.randbytes(16))
data += encode_tlvblock("LicenseEntryIds", b"\x01\x00" + hashlib.sha256(new_pfn.encode("utf-16-le")).digest())
data += encode_tlvblock("LicenseExpirationTime", b"\x00\x00\x00\x00")

if extradata:
    data += extradata

with open(out_lic, "wb") as f:
    f.write(data)