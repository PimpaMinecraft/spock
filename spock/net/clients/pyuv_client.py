import signal
import sys
import os
import logging

import pyuv
from Crypto import Random

from spock.net.eventhandlers import ClientEventHandlers
from spock.net.event import Event
from spock.net import timer, cipher, cflags
from spock.mcp import mcdata, mcpacket
from spock import utils, smpmap, bound_buffer

class Client(object):
	def __init__(self, **kwargs):
		#Grab some settings
		settings = kwargs.get('settings', {})
		for setting in cflags.defstruct:
			val = kwargs.get(setting[1], settings.get(setting[1], setting[2]))
			setattr(self, setting[0], val)

		#Initialize plugin list
		#Plugins should never touch this
		self.timers = []
		self.event_handlers = {ident: [] for ident in mcdata.structs}
		self.event_handlers.update({event: [] for event in cflags.cevents})
		self.event_handlers.update({event: [] for event in cflags.cflags})
		self.plugins = [plugin(self, self.plugin_settings.get(plugin, None)) for plugin in self.plugins]
		self.plugins.insert(0, ClientEventHandlers(self))

		#Initialize socket and poll
		#Plugins should never touch these unless they know what they're doing
		self.loop = pyuv.Loop.default_loop()
		self.tcp = pyuv.TCP(self.loop)

		#Initialize Event Loop/Network variables
		#Plugins should generally not touch these
		self.encrypted = False
		self.kill = False
		self.login_err = False
		self.auth_err = False
		self.rbuff = bound_buffer.BoundBuffer()
		self.sbuff = b''

		#Game State variables
		#Plugins should read these (but generally not write)
		self.world = smpmap.World()
		self.world_time = {
			'world_age': 0,
			'time_of_day': 0,
		}
		self.position = {
			'x': 0,
			'y': 0,
			'z': 0,
			'stance': 0,
			'yaw': 0,
			'pitch': 0,
			'on_ground': False,
		}
		self.health = {
			'health': 20,
			'food': 20,
			'food_saturation': 5,
		}
		self.playerlist = {}
		self.entitylist = {}
		self.spawn_position = {
			'x': 0,
			'y': 0,
			'z': 0,
		}

	#Convenience method for starting a client
	def start(self, host = '0.0.0.0', port = 25565):
		if self.daemon: self.start_daemon()
		if (self.start_session(self.mc_username, self.mc_password)['Response'] == "Good to go!"):
			self.connect(self.handshake, host, port)
			self.loop.run()
		self.exit()

	def emit(self, name, data=None):
		event = (data if name in mcdata.structs else Event(name, data))
		for handler in self.event_handlers[name]:
			handler(name, data)

	def reg_event_handler(self, events, handlers):
		if isinstance(events, str) or not hasattr(events, '__iter__'): 
			events = [events]
		if not hasattr(handlers, '__iter__'):
			handlers = [handlers]

		for event in events:
			self.event_handlers[event].extend(handlers)

	def register_timer(self, timer):
		self.timers.append(timer)

	def connect(self, callback, host = '0.0.0.0', port = 25565):
		if self.proxy['enabled']:
			self.host = self.proxy['host']
			self.port = self.proxy['port']
		else:
			self.host = host
			self.port = port
		print("Attempting to connect to host:", self.host, "port:", self.port)
		self.tcp.connect((self.host, self.port), callback)

	def kill(self):
		self.emit('kill')
		self.kill = True

	def exit(self):
		sys.exit(0)

	def enable_crypto(self, SharedSecret):
		self.cipher = cipher.AESCipher(SharedSecret)
		self.encrypted = True

	def push(self, packet):
		bytes = packet.encode()
		self.tcp.write((self.cipher.encrypt(bytes) if self.encrypted else bytes))
		self.emit(packet.ident, packet)

	def on_read(self, tcp_handle, data, error):
		self.rbuff.append(self.cipher.decrypt(data) if self.encrypted else data)
		try:
			while True:
				self.rbuff.save()
				packet = mcpacket.read_packet(self.rbuff)
				self.emit(packet.ident, packet)
		except bound_buffer.BufferUnderflowException:
			self.rbuff.revert()		

	def start_session(self, username, password = ''):
		self.mc_username = username
		self.mc_password = password

		#Stage 1: Login to Minecraft.net
		if self.authenticated:
			print("Attempting login with username:", username, "and password:", password)
			LoginResponse = utils.LoginToMinecraftNet(username, password)
			if (LoginResponse['Response'] == "Good to go!"):
				print(LoginResponse)
			else:
				print('Login Unsuccessful, Response:', LoginResponse['Response'])
				self.login_err = True
				if self.sess_quit:
					print("Session error, stopping...")
					self.kill = True
				return LoginResponse

			self.username = LoginResponse['Username']
			self.sessionid = LoginResponse['SessionID']
		else:
			self.username = username

		return LoginResponse

	def handshake(self, tcp_handle, error):
		self.SharedSecret = Random._UserFriendlyRNG.get_random_bytes(16)

		#Stage 2: Send initial handshake
		self.push(mcpacket.Packet(ident = 0x02, data = {
			'protocol_version': mcdata.MC_PROTOCOL_VERSION,
			'username': self.username,
			'host': self.host,
			'port': self.port,
			})
		)
		self.tcp.start_read(self.on_read)

	def start_daemon(self, daemonize = False):
		self.daemon = True
		if daemonize:
			utils.daemonize()
			Random.atfork()

		self.pid = os.getpid()
		if self.logfile:
			sys.stdout = sys.stderr = open(self.logfile, 'w')
		if self.pidfile:
			pidf = open(self.pidfile, 'w')
			pidf.write(str(self.pid))
			pidf.close()

	def enable_proxy(self, host, port):
		self.proxy['enabled'] = True
		self.proxy['host'] = host
		self.proxy['port'] = port

	def signal_handler(self, *args):
		self.kill = True
