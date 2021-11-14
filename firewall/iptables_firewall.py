from ipaddress import ip_address
import ipaddress
from common.ports import Ports
import subprocess
import sys
from collections import namedtuple

from multiprocessing.connection import Listener


Rule = namedtuple('Rule', 'protocol, ports, target, ip_address', defaults=(None, None, None, None))

class Commands():
  # https://linux.die.net/man/8/iptables
  APPEND_RULE = '-A'
  INSERT_RULE = '-I'
  DELETE_RULE = '-D'
  NEW_CHAIN = '-N'
  FLUSH_CHAIN = '-F'
  DELETE_CHAIN = '-X'
  CHECK_RULE = '-C'


class GameServerFirewall():
  """ iptables based firewall for taserver's game_server_launcher
  We create new chain in iptables named taserver-$OFFSET. This chain will have a default policy
  of DROP. When a player is connected, we will add a rule which matches that's player's IP -> ACCEPT
  Then we add rules tp the INPUT chain to forward traffic for the game server's ports (7777,7778,9002)+$OFFSET
  to the taserver-$OFFSET chain.
  """

  def __init__(self, ports):
    self.ports = ports
    self.port_range = ','.join([
      str(ports['gameserver1']), str(self.ports['gameserver2']), str(self.ports['game2launcher'])
    ])

    # The chain from which we forward traffic to the offset-specific chain
    self.input_chain = 'INPUT'
    # name of the chain for this instance of game_server_launcher
    self.chain = f'taserver-{ports.portOffset}'

  def add(self, ip_address):
    print(f'Adding accept rule for {ip_address}')
    tcp_rule = Rule(protocol='tcp', ports=self.port_range, target='ACCEPT', ip_address=ip_address)
    udp_rule = Rule(protocol='udp', ports=self.port_range, target='ACCEPT', ip_address=ip_address)
    
    # Prepend rules to accept TCP & UDP traffic from this IP
    # Check if rules already exist to avoid duplicates
    if self._iptables(Commands.CHECK_RULE, self.chain, tcp_rule) != 0:
      self._iptables(Commands.INSERT_RULE, self.chain, tcp_rule)

    if self._iptables(Commands.CHECK_RULE, self.chain, udp_rule) != 0:
      self._iptables(Commands.INSERT_RULE, self.chain, udp_rule)

  def remove(self, ip_address):    
    print(f'Removing accept rule for {ip_address}')
    tcp_rule = Rule(protocol='tcp', ports=self.port_range, target='ACCEPT', ip_address=ip_address)
    udp_rule = Rule(protocol='udp', ports=self.port_range, target='ACCEPT', ip_address=ip_address)

    # Delete rules to accept traffic from this IP
    self._iptables(Commands.DELETE_RULE, self.chain, tcp_rule)
    self._iptables(Commands.DELETE_RULE, self.chain, udp_rule)

  def reset(self):
    print(f'Resetting all iptables rules')
    forward_tcp_rule = Rule(protocol='tcp', ports=self.port_range, target=self.chain)
    forward_udp_rule = Rule(protocol='udp', ports=self.port_range, target=self.chain)

    # Delete forwarding rules from INPUT, if it exists
    # Suppress error output since these rules may not exist
    self._iptables(Commands.DELETE_RULE, self.input_chain, forward_tcp_rule, quiet=True)
    self._iptables(Commands.DELETE_RULE, self.input_chain, forward_udp_rule, quiet=True)

    # Delete the taserver chain, if it exists
    self._iptables(Commands.FLUSH_CHAIN, self.chain, quiet=True)
    self._iptables(Commands.DELETE_CHAIN, self.chain, quiet=True)

    # Create new taserver chain with default rule to drop all traffic
    self._iptables(Commands.NEW_CHAIN, self.chain)
    self._iptables(Commands.APPEND_RULE, self.chain, Rule(target='DROP'))

    # Forward this game server's traffic from INPUT chain to taserver chain
    if self._iptables(Commands.CHECK_RULE, self.input_chain, forward_tcp_rule) != 0:
      self._iptables(Commands.INSERT_RULE, self.input_chain, forward_tcp_rule)
    
    if self._iptables(Commands.CHECK_RULE, self.input_chain, forward_udp_rule) != 0:
      self._iptables(Commands.INSERT_RULE, self.input_chain, forward_udp_rule)

  def _iptables(self, command, chain, rule=Rule(), quiet=False):
    args = ['iptables', command, chain]

    if rule.protocol:
      args += ['-p', rule.protocol]

    if rule.ports:
      args += ['-m', 'multiport', '--dport', rule.ports]

    if rule.target:
      args += ['-j', rule.target]
    
    if rule.ip_address:
      args.extend(['-s', rule.ip_address])

    # Suppress error for rule checks, since they are expected to fail
    if quiet or command == Commands.CHECK_RULE:
      stderr = subprocess.DEVNULL
    else:
      stderr = None

    try:
      return subprocess.call(args, stderr=stderr)
    except Exception as e:
      print(f'Error while running {args}: {repr(e)}')
  

def main():
  offset = int(sys.argv[1])
  ports = Ports(portOffset=offset)
  firewall = GameServerFirewall(ports)

  listener = Listener(('localhost', 6000))
  while True:
    try:
      with listener.accept() as connection:
        command = connection.recv()
        action = command['action']
        if command['action'] == 'reset':
          firewall.reset()
        elif command['action'] == 'add':
          ip = str(ip_address(command['ip']))
          firewall.add(ip)
        elif command['action'] == 'remove':
          ip = str(ip_address(command['ip']))
          firewall.add(ip)
        else:
          print(f'Command "{action}" is not valid')

    except Exception as e:
      import traceback
      traceback.print_exc()
      print(f'Connection failed with: {repr(e)}')

if __name__ == '__main__':
  main()
