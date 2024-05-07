import socket
import sys
import re
import os
import select
import time
import math

# Lab 8 Drone8
# Author: Ross Imbrock

# Initializes socket and exits if there is an error
def init_socket():
    sd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if sd == -1:
        print("socket was set up incorrectly")
        sys.exit(1)
    return sd

# Checks the the port number given is valid
def check_port(port_number):
    # Check for errors in socket creation****
    # Check if the port number is a valid number
    if not (0 <= port_number <= 65535):
        print("Error: Invalid port number. Enter a number 0-65535")
        sys.exit(1)

# Check if the provided IP address is valid
def check_ip(server_ip):
    try:
        socket.inet_aton(server_ip)
    except socket.error:
        print("Error: Bad IP address")
        sys.exit(1)

# Attempts to bind socket with server address
def bind_socket(sd, server_address):
    try:
        sd.bind(server_address)
    except socket.error as e:
        print(f"Binding error: {e}")
        sys.exit(1)

# Receieve data and return if data was received
def receive_data(sd, buffer_size, flags):
    buffer_received = bytearray(buffer_size)
    buffer_length, from_address = sd.recvfrom_into(buffer_received, buffer_size, flags)
    if buffer_length <= 0:
        print("No data received")
        sys.exit(1)
    received_data = buffer_received[:buffer_length].decode()  # Decode only the received data
    return received_data

# Parse message received from client and return resulting dictionary
def parse_message(line):
    pairs = line.split()
    msg_key = None
    msg_value = []
    message_dict = {}
    MSG_FOUND = False
    processing_msg = False
    error = False
    stored_keys = []
    for pair in pairs:
        if not processing_msg and ':' not in pair:
            print("Error: Missing : for a key value pair.")
            error = True
        if ':' in pair:
            key, value = pair.split(':', 1)
            if key in stored_keys:
                print ('Error: duplicate key found:', key)
                error = True
                continue
            else:
                stored_keys.append(key)

            if key == 'msg':
                if MSG_FOUND:
                    print('Error: Only 1 msg key is allowed')
                    error = True
                MSG_FOUND = True
                msg_key = key
                msg_value.append(value)
                processing_msg = True
                if value.endswith('"'):
                    message_dict[msg_key] = ' '.join(msg_value)
                    msg_key = None
                    msg_value = []
                    processing_msg = False
            else:
                message_dict[key] = value
        elif msg_key:
            msg_value.append(pair)
            if pair.endswith('"') or pairs[-1] == pair:
                message_dict[msg_key] = ' '.join(msg_value)
                msg_key = None
                msg_value = []
                processing_msg = False
    return message_dict, error

# Ensure received line is in the correct format and return if it is in boolean form
def validate_line (line):
    code = True
    if '^' in line:
        print ('Error: ^ is not allowed in message')
        code = False
    if ':' not in line:
        print ('Error: Wrong format, expected :')
        code = False
    return code

# Ensure dictionary is in the correct format before printing and return if it is in boolean form
def validate_dict (dictionary):
    required_keys = ['time', 'msg', 'toPort', 'fromPort', 'TTL', 'version', 'flags', 'location', 'send-path', 'seqNumber']
    for key,value in dictionary.items():
        if value == '' or value == ' ':
            return False, 'Error: Key is missing a value'
        if len(str(key)) > 200 or (len(str(value)) > 200):
            return False, 'Error: Maximum variable size is 200 bytes. ' + key + ':'+ value +' violates this condition'
        if key not in required_keys and key != 'type' and key != 'move' and key != 'myLocation':
            return False, ('Error: Illegal key in input ' + '"' + key + '"')
    for key in required_keys:
        if (key not in dictionary):
            # Don't error if its an ACK
            if 'type' not in dictionary and 'move' not in dictionary:
                return False, ('Error: ' + key + ' key not present in input')

    return True,''

# Verify config.file path is valid, and file exists and is not empty. Then execute sending of messages.
def execute_config(config, given_port_number):
    if not os.path.isfile(config):
        print('Config file could not be found. Please enter a different path.')
        sys.exit(1)
    return_location = 0
    with open(config, 'r') as cfg:
        first_char = cfg.read(1)
        cfg.seek(0)
        if not first_char:
            print ("Error: The config file is empty, there are no servers to send to.")
            sys.exit(1)
        else:
            server_locations = {}
            for line in cfg:
                # Take in IP, port, and location from line
                config_line = line.split()
                if len(config_line) != 3:
                    print("Error: Invalid config format")
                    sys.exit(1)
                server_ip, port_number, location = config_line[0], int(config_line[1]), int(config_line[2])

                # Return location of this instance of the program
                if port_number == given_port_number:
                    return_location = location

                # Check validity of ip and port
                check_ip(server_ip)
                check_port(port_number)

                # Assign location to server address
                server_address = (server_ip + ':' + str(port_number))
                server_locations[server_address] = location
            if return_location == 0:
                print('Error server port (fromPort) is not in config.file')
                sys.exit(1)
            return server_locations, return_location

# Send single line to the server
def send_line(sd, buffer_out, server_address):
    rc = sd.sendto(buffer_out.encode(), server_address)
    # Check for possible errors
    if rc < len(buffer_out):
        print("Error: sending line failed")
        sys.exit(1)

# Call send_line on each line in the message the user gives
def send_msg(sd, server_address, msg, port):
    if int(server_address[1]) != int(port):
        if not msg:
            print ("Error: The message is empty, there is nothing to send.")
            sys.exit(1)

        # Split multiple messages into individuals
        if '\n' in msg:
            lines = msg.split('\n')
            for line in lines:
                if line:
                    send_line(sd, line.strip(), server_address)
        # Single line case
        else:
            send_line(sd, msg.strip(), server_address)
    else:
        if re.search(r'move:\d+', msg):
            send_line(sd, msg.strip(), server_address)

# Global variable for sequence numbers
seq_numbers = {}
# Fill in default values for message to send (will change for future labs)
def complete_message(client_input, port_number, location):
    global seq_numbers
    client_input += (' fromPort:' + str(port_number))
    client_input += (' time:' + str(int(time.time())))
    client_input += (' version:8')
    if ('TTL' not in client_input):
        client_input += (' TTL:5')
    if ('flags' not in client_input):
        client_input += (' flags:0')
    client_input += (' location:' + str(location))
    client_input += (' send-path:' + str(port_number))

    toPort = get_user_port(client_input)
    if not toPort:
        toPort = port_number

    if toPort in seq_numbers:
        seq_numbers[toPort] += 1
    else:
        seq_numbers[toPort] = 1
    client_input += (' seqNumber:' + str(seq_numbers[toPort]))

    return client_input

# Find the distance between the current location and sender's location
def find_distance(n, m, current_loc, sender_loc):
    # Cast to ints and start at index 1
    current_loc = int(current_loc) - 1
    sender_loc = int(sender_loc) - 1
    n = int(n)
    m = int(m)

    # Check if both positions are in range
    highest_grid_loc = n * m
    if current_loc >= highest_grid_loc or sender_loc >= highest_grid_loc:
        return True, 0, 'Error: NOT IN GRID'

    # Find current server's position in grid
    current_x = (current_loc // m) + 1
    current_y = (current_loc % m) + 1

    # Find sender's position in grid
    sender_x = (sender_loc // m) + 1
    sender_y = (sender_loc % m) + 1

    # Calculate Euclidean distance
    distance = math.sqrt((sender_x - current_x) ** 2 + (sender_y - current_y) ** 2)

    # Truncate the distance
    trunc_distance = math.floor(distance)
    msg = ''
    if trunc_distance <= 2:
        msg = ''
    else:
        msg = ('Error: OUT OF RANGE\nDrones are ' + str(trunc_distance) + ' spaces apart, the max is 2.')

    return False, trunc_distance, msg

# Check if TTL status allows message to print and update TTL and then optimize before forwarding
def validate_and_optimize(dictionary, n, m, location, sender_location, port, server_locations):
    # Handle move in dictionary 
    if 'move' in dictionary:
        return dictionary, False, False

    # Discard message if TTL is 0
    ttl = int(dictionary['TTL'])
    if ttl == 0:
        return dictionary, True, True

    outOfRange, distance, distance_msg = find_distance(n, m, location, sender_location)
    toPort = int(dictionary['toPort'])
    if distance > 2:
        print("Message out of range")
        return dictionary, True, False
    elif ttl > 0 and distance <= 2:
        if port == toPort:
            return dictionary, False, False
        else:
            # Message not for this node but within range, decrement TTL and forward
            ttl -= 1
            # Optimization of send path
            if ttl > 0 and (str(port) not in dictionary['send-path']):
                dictionary['TTL'] = str(ttl)
                dictionary['location'] = str(location)
                dictionary['send-path'] = (str(dictionary['send-path']) + ',' + str(port))
                print('I am forwarding')
                forward_message(dictionary, server_locations, port)
            else:
                print('I\'m already in the send path! Not forwarding.')
            return dictionary, True, False
    else:
        return dictionary, True, True

# Forward message to all peers besides yourself and the peer who sent the message
def forward_message(dictionary, server_locations, current_port):
    global stored_messages
    message = format_message(dictionary)
    sd = init_socket()
    fromPort = int(dictionary['fromPort'])

    duplicate_msg_found = False
    for msg in stored_messages:
        if msg['fromPort'] == dictionary['fromPort'] and msg['seqNumber'] == dictionary['seqNumber']:
            print('Duplicate message not storing')
            duplicate_msg_found = True
            break
    if not duplicate_msg_found:
        stored_messages.append(dictionary)
        print('Stored message.')

    for address, location in server_locations.items():
        server_ip, port_number = address.split(':')
        port_number = int(port_number)
        # Find a way to make sure sender and receiver do not forward, that is why it is sending so many
        if port_number != current_port:
            server_address = (server_ip, port_number)
            send_msg(sd, server_address, message, current_port)

# Make dictionary into a string
def format_message(dictionary):
    message = ''
    for key, value in dictionary.items():
        message += (str(key) + ':' + str(value) + ' ')
    return message.strip()

# Get port for sequence number count
def get_user_port (input):
    match = re.search(r"toPort:(\d+)", input)
    if match:
        return int(match.group(1))
    return None

# Global variable for received messages
received_messages = {}
# Initialize or update sequence number
def validate_seq(dictionary):
    if dictionary['fromPort'] in received_messages:
        if received_messages[dictionary['fromPort']] == dictionary['seqNumber']:
            return True
    received_messages[dictionary['fromPort']] = dictionary['seqNumber']
    return False

# Send ACK to sender
def send_ACK(dictionary, server_locations, port_number):
    ack_msg = ''

    send_path = ('send-path:' + str(dictionary['toPort']))
    ttl = ' TTL:5'
    version = ' version:' + str(dictionary['version'])
    toPort = (' toPort:' + str(dictionary['fromPort']))
    fromPort = (' fromPort:' + str(dictionary['toPort']))
    seqNumber = (' seqNumber:' + str(dictionary['seqNumber']))
    msg_type = (' type:ACK')
    location = (' location:' + str(dictionary['myLocation']))
    flags = (' flags:' + str(dictionary['flags']))
    time = (' time:' + str(dictionary['time']))
    
    ack_msg = (send_path + ttl + version + toPort + fromPort + seqNumber + msg_type + location + flags + time)
    sd = init_socket()
    for address in server_locations:
        split_addy = address.split(':')
        outgoing_server_ip = split_addy[0]
        outgoing_port_number = int(split_addy[1])
        outgoing_server_address = (outgoing_server_ip, outgoing_port_number)
        if int(outgoing_port_number) != int(port_number):
            send_msg(sd, outgoing_server_address, ack_msg.strip(), int(port_number))

# Global variable for stored messages (for receving and forwarding)
stored_messages = []

# Launch server and wait for client connection
def main():
    global stored_messages
    # Check for correct number of command line inputs
    if len(sys.argv) < 3:
        print("usage is: drone3 <config.file> <port number>")
        sys.exit(1)

    # Validate given port number
    port_number = int(sys.argv[2])
    check_port(port_number)

    # Initialize and bind socket
    sd = init_socket()
    server_address = ('', port_number)
    bind_socket(sd, server_address)

    print('\nEnter values for a NxM drone matrix:')
    n_value = input('Enter the N value: ')
    m_value = input('Enter the M value: ')

    inputs = [sd, sys.stdin]
    mute_prompt = False
    config = sys.argv[1]
    server_locations, location = execute_config(config, port_number)
    while True:
        if not mute_prompt:
            print ('\nEnter a message to send or wait for network traffic:')
        mute_prompt = False
        # Use select with a timeout of 20 seconds
        file_descriptors, _, _ = select.select(inputs, [], [], 20)
        
        if not file_descriptors:
            print("Timed out -- No input detected.")
            for msg in stored_messages:
                updated_TTL = (int(msg['TTL']) - 1)
                if updated_TTL <= 0:
                    stored_messages.remove(msg)
                else:
                    msg['TTL'] = str(updated_TTL)
                    formated_stored_msg = format_message(msg)
                    for address in server_locations:
                        split_addy = address.split(':')
                        outgoing_server_ip = split_addy[0]
                        outgoing_port_number = int(split_addy[1])
                        outgoing_server_address = (outgoing_server_ip, outgoing_port_number)
                        send_msg(sd, outgoing_server_address, formated_stored_msg.strip(), port_number)
            continue
        should_break = False
        for source in file_descriptors:
            # Server received network traffic
            if source == sd:
                received_data = receive_data(sd, 1000, 0)
                validate_line(received_data)
                cli_dict, parse_error = parse_message(received_data)
                error_msg = ''
                dict_validated, error_msg = validate_dict(cli_dict)
                if not dict_validated or parse_error:
                    print(error_msg)
                    continue
                else:
                    # Handle Forwarding
                    cli_dict, discard, mute = validate_and_optimize(cli_dict, n_value, m_value, location, cli_dict['location'], int(port_number), server_locations)
                    if discard:
                        if mute:
                            mute_prompt = True
                        break
                    
                    # Check for Move statement and set location
                    move = False
                    moveMessage = ''
                    if 'move' in cli_dict:
                        location = cli_dict['move']
                        moveMessage =  ('My new location is ' + str(location))
                        outOfRange = False
                        distance = 0
                        distance_msg = ''
                        move = True
                    for msg in stored_messages:
                        updated_TTL = (int(msg['TTL']) - 1)
                        if updated_TTL <= 0:
                            stored_messages.remove(msg)
                        else:
                            msg['TTL'] = str(updated_TTL)
                            if str(msg['fromPort']) == str(port_number):
                                msg['location'] = location
                            formated_stored_msg = format_message(msg)
                            for address in server_locations:
                                split_addy = address.split(':')
                                outgoing_server_ip = split_addy[0]
                                outgoing_port_number = int(split_addy[1])
                                outgoing_server_address = (outgoing_server_ip, outgoing_port_number)
                                send_msg(sd, outgoing_server_address, formated_stored_msg.strip(), port_number)
                    else:
                        # Find Distance
                        outOfRange, distance, distance_msg = find_distance(n_value, m_value, location, cli_dict['location'])
                    cli_dict['myLocation'] = str(location)
                    
                    duplicate = validate_seq(cli_dict)
                    # Handle receiving duplicate ACKs
                    if 'type' in cli_dict and duplicate:
                        print('Recieved a duplicate ACK for seqNumber ' + str(cli_dict['seqNumber']) + ' fromPort ' + str(cli_dict['fromPort']))
                        break

                    # Handle receiving duplicate packets
                    if duplicate:
                        print('Duplicate packet detected! Duplication ACK being sent for seqNumber '+ str(cli_dict['seqNumber']) + ' fromPort ' + str(cli_dict['fromPort']))
                        send_ACK(cli_dict, server_locations, port_number)
                        break
                    
                    # Lab 8 changes
                    duplicate_msg_found = False
                    for msg in stored_messages:
                        if msg['fromPort'] == cli_dict['fromPort'] and msg['seqNumber'] == cli_dict['seqNumber']:
                            print('Duplicate message not storing')
                            duplicate_msg_found = True
                            break
                    if not duplicate_msg_found:
                        stored_messages.append(cli_dict)
                        print('Stored message.')

                    toPort = cli_dict['toPort']
                    if (int(toPort) == int(port_number)):

                        print ('Server received message!')
                        if move:
                            print(moveMessage)
                        if not outOfRange and not move:
                            print (distance_msg)
                            # Send ACK back to sender
                            if 'type' not in cli_dict:
                                print('Sending ACK for seqNumber '+ str(cli_dict['seqNumber']) + ' fromPort ' + str(cli_dict['fromPort']))
                                send_ACK(cli_dict, server_locations, port_number)
                            else:
                                print('Recieved an ACK for seqNumber' + str(cli_dict['seqNumber']) + ' fromPort ' + str(cli_dict['fromPort']))
                            print ('***********************************')
                            print ('Name\t\tValue')
                            for key,value in cli_dict.items():
                                # Simple way to format printing
                                if len(key) > 7:
                                    print(key + '\t' + value)
                                else:
                                    print(key + '\t\t' + value)
                            print ('***********************************')
                        else:
                            if outOfRange:
                                print('Error: NOT IN GRID')
                    else:
                        print('Server received a message directed to a different port')
            # Server received command line input
            elif source == sys.stdin:
                # Read in client input
                CLI_input = sys.stdin.readline().strip()

                # Reconstruct message with all required keys
                if CLI_input:
                    CLI_input = complete_message(CLI_input, port_number, location)

                # Direct send if its a move message
                directPort = get_user_port(CLI_input)
                if re.search(r'move:\d+', CLI_input) and directPort:
                    directAddress = ('', directPort)
                    send_msg(sd, directAddress, CLI_input.strip(), port_number)
                    print('\nSending message:\n"' + CLI_input.strip() + '"\n')
                # Move yourself
                elif re.search(r'move:\d+', CLI_input) and not directPort:
                    myAddress = ('', port_number)
                    CLI_input += (' toPort:' + str(port_number))
                    send_msg(sd, myAddress, CLI_input.strip(), port_number)
                    print('\nSending message:\n"' + CLI_input.strip() + '"\n')
                elif CLI_input and directPort != port_number:
                    # Send file line by line
                    for address in server_locations:
                        split_addy = address.split(':')
                        outgoing_server_ip = split_addy[0]
                        outgoing_port_number = int(split_addy[1])
                        outgoing_server_address = (outgoing_server_ip, outgoing_port_number)
                        send_msg(sd, outgoing_server_address, CLI_input.strip(), port_number)
                    print('\nSending message:\n"' + CLI_input.strip() + '"\n')
                    msg_dict, msg_error = parse_message(CLI_input.strip())
                    if msg_error:
                        print('Error storing message, format violated.')
                    else:
                        stored_messages.append(msg_dict)
        if should_break:
            continue  # Skip to the next iteration of the while loop

if __name__ == "__main__":
    main()
