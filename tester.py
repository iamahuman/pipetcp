import os
import sys
import random
import socket
import subprocess
import time
import threading
import array


stopflag = []

NR = 4224

class PipeTester:

    def __init__(self, rf, wf):
        self.queue = bytearray()
        self.rf = rf
        self.wf = wf
        self.rthread = None
        self.wthread = None
        self.offset = 0

    def on_send(self, data):
        self.queue.extend(data)

    def on_recv(self, data):
        if not self.queue.startswith(data):
            print('RF:', self.rf, 'WF:', self.wf, file=sys.stderr)
            print('OFFSET:', self.offset, file=sys.stderr)
            print('EXPECT:', self.queue[:len(data) + 10].hex(), file=sys.stderr)
            print('ACTUAL:', data.hex(), file=sys.stderr)
            raise ValueError('test fail')
        del self.queue[:len(data)]
        self.offset += len(data)

    def seqdata(self, n):
        elmsize = 4
        iwords, off = divmod(self.offset + len(self.queue), elmsize)
        data = array.array('I', range(iwords, iwords - (n // -elmsize))).tobytes()
        return data[off:]

    def run_send(self):
        try:
            while not stopflag:
                req = random.randrange(NR) + 1
                data = os.urandom(req)
                self.on_send(data)
                while data:
                    n = self.wf.write(data)
                    data = data[n:]
        finally:
            stopflag.append(True)

    def run_recv(self):
        try:
            while not stopflag:
                req = random.randrange(NR) + 1
                data = self.rf.read(req)
                self.on_recv(data)
        finally:
            stopflag.append(True)

    def start(self):
        self.rthread = threading.Thread(target=self.run_recv)
        self.rthread.daemon = True
        self.wthread = threading.Thread(target=self.run_send)
        self.wthread.daemon = True
        self.rthread.start()
        self.wthread.start()

    def join(self):
        self.rthread.join()
        self.wthread.join()


pipe = r"\\.\PIPE\LOCAL\PipeTcpTest_Python_" + str(os.getpid())

lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
lsock.bind(('127.0.0.1', 0))
lsock.listen(1)
addr, port = lsock.getsockname()

proc = subprocess.Popen([sys.argv[1], pipe, addr, str(port)])

sock, cli_addr = lsock.accept()
time.sleep(0.5)

pipefd = os.open(pipe, os.O_RDWR)
piperead = open(pipefd, 'rb', buffering=0)
pipewrite = open(pipefd, 'wb', buffering=0)
sockread = sock.makefile('rb', buffering=0)
sockwrite = sock.makefile('wb', buffering=0)

t1 = PipeTester(piperead, sockwrite)
t2 = PipeTester(sockread, pipewrite)

t1.start()
t2.start()
t1.join()
t2.join()
