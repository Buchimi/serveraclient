# Getting Started
To get started with this project, you will need to have the following software installed on your computer:

A C compiler such as GCC
A text editor or integrated development environment (IDE) such as Visual Studio Code

## Building and Running the Project
To build and run the project, follow these steps:

Clone the project repository to your local machine.
Navigate to the project directory.
Compile the server and client source files using the following commands:
```
gcc -o server server.c
gcc -o client client.c
```
Run the server executable by specifying the port number to listen on:
```
./server <port_number>
```
Run the client executable by specifying the server IP address and port number to connect to:
```
./client <server_ip_address> <port_number>
```
Once the client is connected to the server, you can start sending requests to the server.

## Usage
The server supports the following requests:

- GET <filename> - retrieves the contents of the specified file.
- PUT <filename> - saves the data sent by the client to the specified file.
The client can send requests to the server by entering them on the command line. For example:
```
GET file.txt
PUT file.txt
```
## Limitations
This implementation is a simple example and is not intended to be used in a production environment. It has the following limitations:

The server only supports two types of requests: GET and PUT.
The server does not perform any authentication or authorization checks.
## Conclusion
This project provides a simple implementation of a web server and client in C programming language. It demonstrates how to use file IO and sockets to implement a basic web server and client.
