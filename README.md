# PipeTcp

An asynchronous Windows named pipe server that forwards connections to given TCP server.

Pre-built binaries can be found in [Releases](https://github.com/iamahuman/pipetcp/releases).

## Invocation

- Command Prompt: `pipetcp <PIPE-PATH> <SERVER-HOST> <SERVER-PORT>`
- PowerShell: `.\pipetcp <PIPE-PATH> <SERVER-HOST> <SERVER-PORT>`

Example:

- `pipetcp \\.\PIPE\LOCAL\Dbg1 192.168.34.56 17103`

  Connect to the TCP server at `192.168.34.56:17103`, open a pipe server at `\\.\PIPE\LOCAL\Dbg`, and bridge the pipe client and the TCP server.

## Building (MinGW)

1. Install [Mingw-w64](https://www.mingw-w64.org). Also install `make` if you are on Windows.
2. Run `make`.

## Building (Visual C++)

(TODO)
