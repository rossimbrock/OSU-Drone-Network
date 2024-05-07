# CSE 5462 Lab 8 - Ross Imbrock
This is the final lab for the OSU CSE 5462 Network Programming Class, it follows instructions from Labs 0-8 to create a network of drones.

## How to Run Drone8
- Create a file called `config.file` with your desired IPs, ports, and locations. *Ex. (127.0.0.1 1818 1)*
- Open a terminal window
- Run `make drone8` if you want to use port 20008 or run `python3 drone8.py <config.file> <port number>` otherwise
- Enter the N x M matrix size you would like to use
- Enter your messages, ensuring they follow the key:value format, and have the **toPort** and **msg** keys

Note:
- Additional keys such as **time, fromPort, TTL, version, flags,** and **location** will be added to your message upon sending it
- You may override the **TTL** and **flags** keys with your own
