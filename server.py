# -*- coding: utf-8 -*-
"""
Source:
    http://tools.ietf.org/html/rfc6455
Receive HTTP Request
-Get Sec-WebSocket-Key
-Generate Sec-WebSocket-Accept
    *Append GUID(encrypted in sha1 and encoded in base64) to Sec-Websocket-Key
-Generate a Response header
    With:
        *Connection: upgrade
-Send HTTP Response
-Begin SocketTCP communication

Framing

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-------+-+-------------+-------------------------------+
     |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
     |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
     |N|V|V|V|       |S|             |   (if payload len==126/127)   |
     | |1|2|3|       |K|             |                               |
     +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
     |     Extended payload length continued, if payload len == 127  |
     + - - - - - - - - - - - - - - - +-------------------------------+
     |                               |Masking-key, if MASK set to 1  |
     +-------------------------------+-------------------------------+
     | Masking-key (continued)       |          Payload Data         |
     +-------------------------------- - - - - - - - - - - - - - - - +
     :                     Payload Data continued ...                :
     + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
     |                     Payload Data continued ...                |
     +---------------------------------------------------------------+
"""
# Imports
import json
import socket
import base64
import hashlib
import time
# Constants
GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
# GUID --> WEBSOCKET'S magic number (we send it to the client concatenated  with the Sec-Websocket-Key)
http_response = "HTTP/1.1 101 Switching Protocols\r\n" + \
                "Upgrade: websocket\r\n" + "Connection: Upgrade\r\n" + \
                "Sec-WebSocket-Accept: {0}\r\n\r\n"
Port = 5555  # Port where the server is running
Host = 'localhost'  # Host where the server is running
n = hashlib.sha1()  # Instantiate an hashlib object which help us with the sha1 encryption
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((Host, Port))
s.listen(5)  # How many clients we are expecting to listen?
print('Set up ready! Serving in:  \n' + 'HOST: ' + Host + '\nPORT: ' + str(Port))
# Decode the rawData that come from the client
def decoding(rawData):
    print(rawData)
    if rawData:
        print('DECODING')
        # Append each byte sorted by their position. This make us work easier because we can modify every byte easily
        a = 0
        result = ''
        mask = 0
        length = 0
        decodedData = []  # It stores the contents of the unmasked data
        length = rawData[1] and 128  # Filtering the data to get the length of the length stream
        if length == 126:
            a = 3  # How long is the length stream?
            mask = rawData[3:7]
        elif length == 127:
            a = 9  # How long is the length stream?
            mask = rawData[9:13]
        else:  # If the length is not 127 nor 126 the length stream is 1 byte
            a = 2  # How long is the length stream?
            mask = rawData[2:6]
        for i in range(4 ,len(rawData) - a):  # Loop between all the elements of the masked data (below mask bytes)
            decodedData.append(rawData[i+a] ^ mask[i % 4])  # Unmask every data
        for i in range(0, len(decodedData)):
            result += chr(decodedData[i])
        print('Decoding has succesfully completed')
        return result
    else:
        print('Decoding has failed due data is an empty variable')
        return None

def code(rawData):
    print('CODING:', rawData)
    result = ''
    encodedData = []

    if rawData:
        encodedData.append(129)  # 1st Byte (data type, etc)

        if type(rawData) == dict:
            rawData = json.dumps(rawData)
        length = len(rawData)  # Raw data's length
        if 0 <= length <= 125:
            encodedData.append(length)
            print(encodedData)
        elif 126 <= length <= 65535:
            encodedData.append(126)
            encodedData.append((length >> 8) and 255)
            encodedData.append(length and 255)
            print(encodedData)
        else:
            encodedData.append(127)
            encodedData.append((length >> 56) and 255)
            encodedData.append((length >> 48) and 255)
            encodedData.append((length >> 40) and 255)
            encodedData.append((length >> 32) and 255)
            encodedData.append((length >> 24) and 255)
            encodedData.append((length >> 16) and 255)
            encodedData.append((length >> 8) and 255)
            encodedData.append(length and 255)
            print(encodedData)

        result = bytes(encodedData) + rawData.encode('utf-8')
        #for i in range(0, len(encodedData)):
        #    result += encodedData[i]
        #    print(result.encode('utf-8'))

        print('Coding has succesfully completed. ', result)
        return result
    else:
        print('Coding has failed due data is an empty variable')
        return None

i = 0
client, address = s.accept()  # Open a new connection
print('Connection with: ' + address[0] + ':' + str(address[1]))
data = client.recv(1024)  # Receive 1024 length data
if data:
    key = ''
o = ''
data = data.decode('utf-8')
data = data[data.find('Sec-WebSocket-Key')+19:]  # From Sec-WebSocket-Key begining + 19 ("Sec-WebSockey-Key"'s length') to the end of the line

for i in data:  # Analize every char and if it's \r (line end) it takes the data between Sec-Websocket-key and the first \r
    if i == '\r':
        break
    else:
        key += i
key += GUID
n.update(key.encode('ascii'))  # Encrypt key + Guid in sha1
o = base64.b64encode(n.digest())  # toBase64
http_response = http_response.format(o.decode('ascii')) #  replace {0} in the http_response with o (base64(sha1(GUID + Sec-WebSocket-Key)))

client.send(http_response.encode('utf-8'))  # Send http header to the client and get a Switching protocol 101
print('Switching Protocols 101')
while True:
        # Testing
        string_ = decoding(client.recv(1024))  # Get value from client
        print(string_)  # Decode the raw value
        # print(decoding(client.recv(1024)))  # Append data recived from client
        # time.sleep(1)  # Wait 1 second
        client.send(code('hola' + string_))
        # client.send(code('HOLA' + string_))  # Send coded data to client

s.close()