# import socket module
from socket import *
# In order to terminate the program
import sys


def webServer(port=13331):
  #Create a TCP socket
  serverSocket = socket(AF_INET, SOCK_STREAM)
  #Associate the server port number with this socket
  serverSocket.bind(("", port))
  #Wait and listen for some client
  serverSocket.listen(1)

  while True:
    #Establish the connection
    #print('Ready to serve...')
    #When the client contact the server we call accept
    #to create a new socket for this conversation
    connectionSocket, addr = serverSocket.accept()
    try:

      try:
        message = connectionSocket.recv(1024).decode()
        filename = message.split()[1]
        f = open(filename[1:])
        outputdata = f.readlines()
        f.close()
        #Send the status line into the socket
        connectionSocket.send("HTTP/1.1 200 OK\r\n".encode())
        #Send one HTTP header line into socket.
        connectionSocket.send("Content-Type: text/html\r\n".encode())
        connectionSocket.send("\r\n".encode())
        #Send the content of the requested file to the client
        for i in range(0, len(outputdata)):
          connectionSocket.send(outputdata[i].encode())

        connectionSocket.send("\r\n".encode())
        connectionSocket.close()
      except IOError:
        # Send response message for file not found (404)
        connectionSocket.send("HTTP/1.1 404 Not Found\r\n".encode())
        connectionSocket.send("\r\n".encode())
        #Close client socket
        connectionSocket.close()

    except (ConnectionResetError, BrokenPipeError):
      pass

  serverSocket.close()
  sys.exit()  # Terminate the program after sending the corresponding data

if __name__ == "__main__":
  webServer(13331)
