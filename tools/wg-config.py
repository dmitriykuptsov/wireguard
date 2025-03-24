# Sockets
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connec(('127.0.0.1', 10000))

commands = {
    "list": [
        "routes"
    ],
    "add": {
        "route": ["<destination ip> <mask> <base 64 encoded public key> <peer> <port>"]
    },
    "status": []
}

reading = True

while reading:
    print('Enter command to send to wg server:')
    s = None
    command = ""
    while True:
        data = input()
        if data == '\n':
            s.send(command.encode('ASCII'))
            break
        if data == '\t':
            subcommands = command.split(" ")
            last = subcommands[-1]
            if s:
                s = commands[last]
            
            print("")
        if data == "exit":
            reading = False
            break
