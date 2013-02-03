import logging
from spock import utils
from spock.mcp import mcdata
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA


handles = {}
def handle(ident):
	def inner(cl):
		handles[ident] = cl
		return cl
	return inner

class BaseHandle:
	@classmethod
	def handle(self, client, packet):
		if packet.direction == mcdata.SERVER_TO_CLIENT:
			self.ToClient(client, packet)
		elif packet.direction == mcdata.CLIENT_TO_SERVER:
			self.ToServer(client, packet)
		else:
			return 0

@handle(0x00)
class handle00(BaseHandle):
	def ToClient(self, client, packet):
		client.push(Packet(ident = 0x00, data = {
				'value': p.data['value']
				})
		)

@handle(0xFC)
class handleFC(BaseHandle):
	def ToClient(self, client, packet):
		#Stage 5: Enable encryption and send Client Status
		client.enable_crypto(client.SharedSecret)
		client.push(mcpacket.Packet(ident = 0xCD, data = {
			'payload': 0,
			})
		)


@handle(0xFD)
class handleFD(BaseHandle):
	@classmethod
	def ToClient(self, client, packet):
		#Stage 3: Authenticate with session.minecraft.net
		pubkey = packet.data['public_key']
		serverid = utils.HashServerId(packet.data['server_id'], client.SharedSecret, pubkey)
		SessionResponse = utils.AuthenticateMinecraftSession(client.username, client.sessionid, serverid)
		if (SessionResponse != 'OK'):
			logging.error('Session Authentication Failed, Response: %s', SessionResponse)
			return

		#Stage 4: Send an Encryption Response
		RSACipher = PKCS1_v1_5.new(RSA.importKey(pubkey))
		encryptedSanityToken = RSACipher.encrypt(str(packet.data['verify_token']))
		encryptedSharedSecret = RSACipher.encrypt(str(SharedSecret))
		client.push(mcpacket.Packet(ident = 0xFC, data = {
			'shared_secret': encryptedSharedSecret,
			'verify_token': encryptedSanityToken,
			}).encode()
		)