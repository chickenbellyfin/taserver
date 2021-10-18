import ctypes
import gevent.subprocess as sp
import os
import subprocess
from common.errors import FatalError


class GameServerProcess():
  """
  Standard game server process running in Windows
  """

  def __init__(self, working_dir, abslog, port, control_port, dll_config_path=None):
    self.working_dir = working_dir
    self.abslog = abslog
    self.port = port
    self.control_port = control_port
    self.dll_config_path = dll_config_path

  def start(self):
    exe_path = os.path.join(self.working_dir, 'TribesAscend.exe')
    args = [exe_path, 'server',
      f'-abslog={self.abslog}',
      f'-port={self.port}',
      f'-controlport', str(self.control_port)
    ]

    if self.dll_config_path is not None:
      args.extend(['-tamodsconfig', self.dll_config_path])

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


class WineGameServerProcess():
  """
  Manage a game server process running in linux using Wine (https://www.winehq.org/)
  wine must be installed in the environment along with vcrun2017 from winetricks
  """

  def __init__(self, working_dir, abslog, port, control_port, dll_config_path=None):
    self.working_dir = working_dir
    self.abslog = abslog
    self.port = port
    self.control_port = control_port
    self.dll_config_path = dll_config_path

  def start(self):
    exe_path = os.path.join(self.working_dir, f'TribesAscend{self.port}.exe')
    args = ['wine', exe_path, 'server',
      f'-abslog={self.abslog}',
      f'-port={self.port}',
      f'-controlport', str(self.control_port)
    ]
    print(f"RUN {args}")

    if self.dll_config_path is not None:
      args.extend(['-tamodsconfig', self.dll_config_path])

    self.process = sp.Popen(args, cwd=self.working_dir)
    self.pid = self._find_tribes_windows_pid()
    if self.pid is None:
      raise FatalError(f'Failed to start game server process {args}')
  
  def poll(self):
    return self.process.poll()

  def wait(self):
    return self.process.wait()
  
  def terminate(self):
    self.process.terminate()

  def freeze(self):
    # TODO
    return True

  def unfreeze(self):
    # TODO
    return True

  def _find_tribes_windows_pid(self):
    """
    Finds the windows process id (wpid) of TribesAscend.exe running in wine. The matching process's
    command must also match the port since there will be at least two TribesAscend.exe's running.
    InjectorStandalone.exe must be supplied with the wpid, not the linux pid (upid) to find the
    process when running under wine.
    https://wiki.winehq.org/Wine_Developer%27s_Guide/Debugging_Wine#Processes_and_threads:_in_underlying_OS_and_in_Windows
    """

    # list wine processes
    wine_pids = subprocess.check_output(['winedbg', '--command', 'info proc']).decode('utf-8')
    print(wine_pids)
    # find process for TribesAscend.exe which matches the port number
    for line in wine_pids.split('\n'):
      if 'TribesAscend' in line and str(self.port) in line:
        # First column in line is wpid
        return int(line.strip().split(' ')[0], 16)
