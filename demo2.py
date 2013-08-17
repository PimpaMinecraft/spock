from spock.net.clients.pyuv_client import Client
from plugins import DebugPlugin
from login import username, password

plugins = [DebugPlugin.DebugPlugin]
client = Client(plugins = plugins, username = username, password = password)
client.start()