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
# Constants
GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
# GUID --> WEBSOCKET'S magic number (we send it to the client concatenated  with the Sec-Websocket-Key)
http_response = "HTTP/1.1 101 Switching Protocols\r\n" + \
                "Upgrade: websocket\r\n" + "Connection: Upgrade\r\n" + \
                "Sec-WebSocket-Accept: {0}\r\n\r\n"
Port = 9999  # Port where the server is running
Host = 'localhost'  # Host where the server is running
n = hashlib.sha1()  # Instantiate an hashlib object which help us with the sha1 encryption
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((Host, Port))
s.listen(5)  # How many clients we are expecting to listen?
print('Set up ready! Serving in:  \n' + 'HOST: ' + Host + '\nPORT: ' + str(Port))
# Decode the rawData that come from the client
def toHexString(num):
    return chr(num)
def decoded_s(rawData):
    # Append each byte sorted by their position. This make us work easier because we can modify every byte easily
    a = 0
    mask = 0
    length = 0
    decodedData = []  # It stores the contents of the unmasked data
    length = rawData[1] and 128  # Filtering the data to get the length of the length steam
    if length == 126:
        a = 2  # How long is the length stream?
        mask = rawData[3:7]
        print('Option2 - 2 bytes. Mask = ', mask)
    elif length == 127:
        a = 8  # How long is the length stream?
        mask = rawData[9:13]
        print('Option 3 - 8 bytes. Mask = ', mask)
    else:  # If the length is not 127 nor 126 the length stream is 1 byte
        a = 1  # How long is the length stream?
        mask = rawData[2:6]
        print('Option1 - 1 byte. Mask = ', mask)
    a += 1  # Adding the first byte of the stream (data type byte is always in the data's stream)
    for i in range(len(rawData) - a):  # Loop between all the elements of the masked data (below mask bytes)
        decodedData.append(rawData[i+a] ^ mask[i % 4])  # Unmask every data
    for i in range(0, len(decodedData)):
        decodedData[i] = chr(decodedData[i])
    print('Decoding has succesfully complete\nData is: ', decodedData)
    return decodedData


def code(rawData):
    result = ''
    mainData = []
    encodedData = []
    if rawData:
        encodedData.append(1)  # 1st Byte (data type, etc)
        if type(rawData) == dict:
            rawData = json.dumps(rawData)
        length = len(rawData)  # Raw data's length
        print(length)

        for i in range(0, length):
            mainData.append(ord(rawData[i]))

        if 0 <= length <= 125:
            print('Option 1')
            encodedData.append(length)

        elif 126 <= length <= 65535:
            print('Option 2')
            encodedData.append(126)
            encodedData.append((length >> 8) and 255)
            encodedData.append(length and 255)
        else:
            print('Option 3')
            encodedData.append(127)
            encodedData.append((length >> 56) and 255)
            encodedData.append((length >> 48) and 255)
            encodedData.append((length >> 40) and 255)
            encodedData.append((length >> 32) and 255)
            encodedData.append((length >> 24) and 255)
            encodedData.append((length >> 16) and 255)
            encodedData.append((length >> 8) and 255)
            encodedData.append(length and 255)

        for i in mainData:
            print(encodedData)
            encodedData.append(i)
        for i in range(len(encodedData)):
            print(encodedData)
            encodedData[i] = toHexString(encodedData[i])

        for i in encodedData:
            result += i

        print(result.encode('utf-8'))
        return result


while True:
    client, address = s.accept()  # Open a new connection
    print('Connection with: ' + address[0] + ':' + str(address[1]))
    data = client.recv(1024)  # Receive 1024 length data
    print(data)
    if len(data) > 0:
        data_ = ''
        o = ''
        data = data.decode('utf-8')
        data = data[data.find('Sec-WebSocket-Key')+19:]
        for i in data:
            if i == '\r':
                data = data[:len(data)-1]
                break
            else:
                data_ += i
        data_ += GUID
        n.update(data_.encode('ascii'))
        o = base64.b64encode(n.digest())
        http_response = http_response.format(o.decode('ascii'))
        client.send(http_response.encode('utf-8'))
        string_ = client.recv(1024)
        decoded_s(string_)
        client.send(code('hello').encode('utf-8'))