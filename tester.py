import os
import sys
import random
import socket
import subprocess
import time
import threading
import array


stopflag = []

DURATION = 60
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
        except:
            stopflag.append(True)
            raise

    def run_recv(self):
        try:
            while not stopflag:
                req = random.randrange(NR) + 1
                data = self.rf.read(req)
                self.on_recv(data)
        except:
            stopflag.append(True)
            raise

    def start(self):
        self.rthread = threading.Thread(target=self.run_recv)
        self.wthread = threading.Thread(target=self.run_send)
        self.rthread.start()
        self.wthread.start()

    def join(self):
        self.rthread.join()
        self.wthread.join()

def do_test(sock, pipefd):
    piperead = os.fdopen(pipefd, 'rb', buffering=0, closefd=False)
    pipewrite = os.fdopen(pipefd, 'wb', buffering=0, closefd=False)
    sockread = sock.makefile('rb', buffering=0)
    sockwrite = sock.makefile('wb', buffering=0)

    timer = threading.Timer(DURATION, function=stopflag.append, args=(False,))
    t1 = PipeTester(piperead, sockwrite)
    t2 = PipeTester(sockread, pipewrite)

    timer.start()
    t1.start()
    t2.start()
    try:
        t1.join()
        t2.join()
    except:
        stopflag.append(True)
        t1.join()
        t2.join()
        raise
    finally:
        timer.cancel()


if __name__ == '__main__':
    pipe_name = r"\\.\PIPE\LOCAL\PipeTcpTest_Python_" + str(os.getpid())

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP) as lsock:
        lsock.bind(('127.0.0.1', 0))
        lsock.listen(1)
        addr, port = lsock.getsockname()

        proc = subprocess.Popen([sys.argv[1], pipe_name, addr, str(port)])
        try:
            sock, cli_addr = lsock.accept()
            with sock:
                time.sleep(0.5)

                pipefd = os.open(pipe_name, os.O_RDWR)
                try:
                    do_test(sock, pipefd)
                finally:
                    os.close(pipefd)
        finally:
            proc.terminate()
            proc.wait()

    if any(stopflag):
        sys.exit(1)
