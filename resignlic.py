from bs4 import BeautifulSoup
from xml.etree import ElementTree as ET
from base64 import b64decode, b64encode
from datetime import datetime
from time import time
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from ecdsa import SigningKey
from copy import copy
import argparse, re

# TODO: Implement SPLicenseBlock parser

CLIPUP_ECC_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgPJp69Tr9nAvAHi3B
2dr5jenY4MkTwy4L/ahplSNxvgahRANCAATC/nluDYXrQHgi9STrd2kEhS4cKfTD
URm5vYGwUG1Jxva69OJEUiF2sfMhYGnCDYHrLM5ndcA0s43ie1+z3y1t
-----END PRIVATE KEY-----"""

clipup_eckey = SigningKey.from_pem(CLIPUP_ECC_KEY_PEM, hashfunc=SHA256.new)

def xml_open(xmlf):
    with open(xmlf) as f:
        cont = f.read()
    
    return BeautifulSoup(cont, "xml")

def xml_save(xml, path):
    with open(path, "wb") as f:
        f.write(canonicb(xml))

def iso_date(t):
    return datetime.fromtimestamp(t).isoformat() + "Z"

def sha256(s):
    return SHA256.new(s).digest()

def b64sencode(s):
    return b64encode(s).decode()

def b64ssencode(s):
    return b64sencode(s.encode())

def b64sdecode(s):
    return b64decode(s).decode()

def hashb64(s):
    return b64sencode(sha256(s))

def canonicb(x):
    return ET.canonicalize(str(x), strip_text=True).encode()

def decode_tsl(tsl, log=False):
    if tsl.SPLicenseBlock:
        licblock = b64decode(tsl.SPLicenseBlock.text)
    else:
        licblock = None
    
    pubkey = clipup_eckey.get_verifying_key()
    
    sig_inf = tsl.SignedInfo
    sig_inf.attrs["xmlns"] = "http://www.w3.org/2000/09/xmldsig#"
    sig_val = b64decode(tsl.SignatureValue.text)
    sig_data = canonicb(sig_inf)
    
    try:
        valid = pubkey.verify(sig_val, sig_data)
    except:
        valid = False
    
    if log:
        print("TSL Information:")
        print(f"Valid: {valid}")
    
    return licblock, valid

def resign_lic(tsl, licblock=None):
    sig_tag = copy(tsl.License.Signature)
    tsl.License.Signature.decompose()
    
    if licblock:
        if tsl.License.SPLicenseBlock is None:
            tsl.License.append(tsl.new_tag("SPLicenseBlock"))
        
        tsl.SPLicenseBlock.string = b64sencode(licblock)
    
    
    hash = hashb64(canonicb(tsl))
    sig_tag.SignedInfo.DigestValue.string = hash
    
    sig_tag.SignedInfo.attrs["xmlns"] = "http://www.w3.org/2000/09/xmldsig#"
    sig = b64sencode(clipup_eckey.sign_deterministic(canonicb(sig_tag.SignedInfo)))
    del sig_tag.SignedInfo.attrs["xmlns"]
    
    sig_tag.SignatureValue.string = sig
    
    tsl.License.append(sig_tag)
    
    return tsl

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", help="Mode: encode, decode")
    parser.add_argument("license", nargs="?", default="", help="Data/path")
    parser.add_argument("licblock", help="Type: tslraw, tslconv, ticket")
    parser.add_argument("--output", "-o", help="Output path", default="edit.xml")
    args = parser.parse_args()
    
    licblock = None
    
    tsl = xml_open(args.license)
    
    if args.mode == "encode":
        with open(args.licblock, "rb") as f:
            licblock = f.read()
        
        tsl = resign_lic(tsl, licblock)
        xml_save(tsl, args.output)
    elif args.mode == "decode":
        licblock_out, valid = decode_tsl(tsl, log=False)
        
        if licblock_out and args.licblock:
            with open(args.licblock, "wb") as f:
                f.write(licblock_out)