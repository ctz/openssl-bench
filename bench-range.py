import subprocess

suite = 'AES128'

print 'len,send,recv'

for len in [16, 32, 64, 128, 512, 1024, 4096, 8192, 32768, 65536, 131072, 262144, 1048576]:
    out = subprocess.check_output(['./bench', 'bulk', suite, str(len)])
    lines = out.splitlines()

    for l in out.splitlines():
        if l.startswith('send: '):
            send = float(l.split()[1])
        if l.startswith('recv: '):
            recv = float(l.split()[1])

    print '%d,%g,%g' % (len, send, recv)
