import socket
print("Testing socket.socketpair()...", flush=True)
s1, s2 = socket.socketpair()
print("socketpair succeeded!", flush=True)
s1.close()
s2.close()
print("Closed!", flush=True)
