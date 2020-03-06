import ecdsa
import binascii
import base58
import hashlib
import json
import requests
import time
from ecdsa import SigningKey
from ecdsa import VerifyingKey, SECP256k1

class BitForwardTransportException(Exception):
	pass

class client:
	ap = '\x4B\xE0\x00'
	def __init__(self, priv, pub, auth=None):
		self.private = SigningKey.from_string(priv.decode('hex'), curve=SECP256k1)
		self.public = pub
		self.auth = auth
	def bin2hex(self, msg):
		return binascii.hexlify(msg)
	def hex2bin(self, msg):
		return binascii.unhexlify(msg)
	def hash256(self, msg):
		s = hashlib.new('sha256', msg).digest()
		r = hashlib.new('sha256', s).digest()
		return r #hashlib.sha256(hashlib.sha256(msg).digest()).digest()
	def hash160(self, msg):
		s = hashlib.new('sha256', msg).digest()
		r = hashlib.new('ripemd160', s).digest()
		return r
	def checkSum(self, msg):
		s = hashlib.new('sha256', msg).digest()
		r = hashlib.new('sha256', s).digest()
		return r[0:4]
	def _public(self):
		pubKeyHex = self.private.verifying_key.to_string('compressed')
		pubhash = '\x00'+self.hash160(pubKeyHex)
		return base58.b58encode(pubhash+self.checkSum(pubhash))
	def address(self, pubKeyHex = None):
		if not pubKeyHex:
			pubKeyHex = self.private.verifying_key.to_string('compressed')
		pubhash = self.hash160(pubKeyHex)
		script = '\x00\x14'+pubhash
		scriptHash = self.ap+self.hash160(script)
		checksum = self.checkSum(scriptHash)
		return base58.b58encode(scriptHash+checksum)
	def getPrivateHex(self):
		return self.private.to_string()
	def _sign(self, msg):
		msgHash = self.hash256(msg)
		return self.private.sign_digest(msgHash, k=162897322)
	def sign(self, msg):
		msgHash = self.hash256(msg)
		sig = self.private.sign_digest(msgHash, k=162897322)
		vklist = VerifyingKey.from_public_key_recovery_with_digest(sig, msgHash, curve=SECP256k1)
		rp = None
		if self.address(vklist[0].to_string('compressed')) == self.address():
			rp = '30'
		if self.address(vklist[1].to_string('compressed')) == self.address():
			rp = '31'
		if rp:
			sig = rp+sig.encode('hex')
		return base58.b58encode(sig.decode('hex'))
	def keyFromSignature(self, msg, signature):
		msgHash = self.hash256(msg)
		sigBin = base58.b58decode(signature)
		rp = ord(sigBin[:1]) - ord('0')
		vklist = VerifyingKey.from_public_key_recovery_with_digest(sigBin[1:], msgHash, curve=SECP256k1)
		return vklist[rp]
	def addressFromSignature(self, msg, signature):
		key = self.keyFromSignature(msg, signature)
		return self.address(key.to_string('compressed'))
	def _request(self, method, msg):
		msg['time'] = time.time()
		url = 'https://xb0ct.com/api/bf/v1/BTC/{method}/'.replace('{method}', method)
		res = requests.post(
			url,
			data = {
				'data': json.dumps(msg),
				'sign': self.sign(json.dumps(msg))
			},
			headers = {'api-key': self.address()},
			auth = self.auth
		)
		if res.status_code != 200:
			raise BitForwardTransportException(res.reason)
			return False
		recv = res.json()
		sign = recv['sign']
		msg = json.loads(recv['data'])
		if msg['error']:
			raise BitForwardTransportException(msg['data'])
			return False
		signer = self.addressFromSignature(recv['data'], sign.encode())
		msg['sign'] = sign
		msg['signer'] = signer
		return msg
	def ping(self):
		return self._request('ping', {})
	def createAccount(self):
		ping = self.ping()
		print "#!/usr/bin/env python2.7"
		print 
		print "from bitForward import bitForward"
		print 
		print "bf = bitForward("
		print "  '"+self.getPrivateHex().encode('hex')+"',"
		print "  '"+ping['signer']+"',"
		print ")"
		print "res = bf.ping()"
		print "print( ('success' if res['signer'] == '"+ping['signer']+"' else 'error') )"
