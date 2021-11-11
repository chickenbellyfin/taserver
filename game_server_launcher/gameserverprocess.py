import ctypes
import gevent.subprocess as sp
import os
from .inject import inject


class GameServerProcess():
  """
  Standard game server process running in Windows
  """

  def __init__(
    self, 
    working_dir,
    abslog,
    port,
    control_port,
    dll_to_inject,
    dll_config_path=None,
    use_external_port=False,
    ):

    self.working_dir = working_dir
    self.abslog = abslog
    self.port = port
    self.control_port = control_port
    self.dll_to_inject = dll_to_inject
    self.dll_config_path = dll_config_path
    self.use_external_port = use_external_port

  def start(self):
    exe_path = os.path.join(self.working_dir, 'TribesAscend.exe')
    args = [exe_path, 'server',
      f'-abslog={self.abslog}',
      f'-port={self.port}',
      f'-controlport', str(self.control_port)
    ]

    if self.dll_config_path is not None:
      args.extend(['-tamodsconfig', self.dll_config_path])
    
    # By default, TAMods-server will listen on port-100/tcp. If udpproxy is not running,
    # -noportoffset will allow TAMods server to still listen on the same port as the game server's udp.
    if self.use_external_port:
      args.extend(['-noportoffset'])

    self.process = sp.Popen(args, cwd=self.working_dir)
    self.pid = self.process.pid

  def poll(self):
    return self.process.poll()

  def wait(self):
    return self.process.wait()

  def terminate(self):
    self.process.terminate()

  def freeze(self):
    return ctypes.windll.kernel32.DebugActiveProcess(self.pid)

  def unfreeze(self):
    return ctypes.windll.kernel32.DebugActiveProcessStop(self.pid)
  
  def inject(self):
    inject(self.process.pid, self.dll_to_inject)
