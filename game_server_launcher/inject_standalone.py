import subprocess

def inject(injector_path, pid, path_to_dll, use_wine=False):
  try:
    args = [injector_path, str(pid), path_to_dll]
    if use_wine:
      args = ['wine'] + args
    result = subprocess.check_output(args)
    print(result)
  except subprocess.CalledProcessError as e:
    print(f'{e}: {e.output}')
  return