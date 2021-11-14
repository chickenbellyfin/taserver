from multiprocessing.connection import Client

commands = [
  {
    'action': 'reset'
  },
  {
    'action': 'add',
    'ip': '1.2.3.4'
  },
  {
    'action': 'remove',
    'ip': '192.168.0.2'
  }
]


for command in commands:
  with Client(('localhost', 6000)) as client:
    client.send(command)