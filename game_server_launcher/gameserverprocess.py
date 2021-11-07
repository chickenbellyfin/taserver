import ctypes
import gevent.subprocess as sp
import os
import signal
import subprocess
import time
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
  wine (32-bit) must be installed in the environment along with vcrun2017 from winetricks
  """

  def __init__(self, server, working_dir, abslog, port, control_port, dll_config_path=None, wait_time_secs=5):
    self.working_dir = working_dir
    self.abslog = abslog
    self.port = port
    self.control_port = control_port
    self.dll_config_path = dll_config_path
    self.server = server[-1:] # 1 or 2
    self.wait_time_secs = int(wait_time_secs)
    self.tribes_exe = os.path.join(self.working_dir, f'TribesAscend{self.server}.exe')

  def start(self):
    # Starting with wineconsole instead of wine saves > 300MB of memory
    args = ['wineconsole', self.tribes_exe, 'server',
      f'-abslog={self.abslog}',
      f'-port={self.port}',
      f'-controlport', str(self.control_port),
      '-noportoffset'
    ]

    if self.dll_config_path is not None:
      args.extend(['-tamodsconfig', self.dll_config_path])

    print(f"Starting game server with command: {args}")
    self.process = sp.Popen(args, cwd=self.working_dir)
    

    self.pid = None # PID is the wine PID. We need to use this for DLL injection
    self.upid = None  # UPID is unix PID, which we need to use for freeze/unfreeze
    
    # sometimes the wine process does not get shown immediately
    # poll until we see it
    start_time = time.time()
    while time.time() < start_time + self.wait_time_secs:
      if self.pid is None:
        self.pid = self._find_tribes_windows_pid()
      if self.upid is None:
        self.upid = self._find_tribes_linux_pid()
      if self.upid and self.upid:
        break

      time.sleep(1)

    if self.pid is None:
      raise FatalError(f'Failed to find wpid of game server process: {args}')

    if self.upid is None:
      raise FatalError(f'Failed to find upid of game server process: {args}')
  
  def poll(self):
    return self.process.poll()

  def wait(self):
    return self.process.wait()
  
  def terminate(self):
    self.process.terminate()

  def freeze(self):
    os.kill(self.upid, signal.SIGSTOP)
    return True

  def unfreeze(self):
    os.kill(self.upid, signal.SIGCONT)
    return True

  def _find_tribes_linux_pid(self):
    """
    Finds the unix process id (upid) of TribesAscend.exe. Because we launched with wineconsole,
    the actual game process (TribesAscend.exe) will be a child of it, so we need to use its pid 
    instead of wineconsole's to freeze/unfreeze the game server.
    https://man7.org/linux/man-pages/man5/proc.5.html
    """
    for pid in os.listdir('/proc'):
      if pid.isdigit():
        try:
          with open(os.path.join('/proc', pid, 'cmdline')) as cmd:
            if cmd.read().startswith(self.tribes_exe):
              print(f"Found {self.tribes_exe} in /proc/{pid}")
              return int(pid)
        except Exception as e:
         pass
    print(f"Did not find {self.tribes_exe} in /proc")
    return None

  def _find_tribes_windows_pid(self):
    """
    Finds the windows process id (wpid) of TribesAscend.exe running in wine. The matching process's
    command must also match the server id since there will be at least two TribesAscend.exe's running.
    InjectorStandalone.exe must be supplied with the wpid, not the linux pid (upid) to find the
    process when running under wine.
    https://wiki.winehq.org/Wine_Developer%27s_Guide/Debugging_Wine#Processes_and_threads:_in_underlying_OS_and_in_Windows
    """

    # list wine processes
    wine_pids = subprocess.check_output(['winedbg', '--command', 'info proc']).decode('utf-8')
    print(wine_pids)
    # find process for TribesAscend.exe which matches the port number
    for line in wine_pids.split('\n'):
      if f'TribesAscend{self.server}' in line:
        # First column in line is wpid
        return int(line.strip().split(' ')[0], 16)
