import hashlib
from queue import Queue
import re
import socket
import sys
import time
from time import sleep
import threading

class Server:
    """
    A class to implement the server side of the rdt protocol
    """
    def __init__(self, ip="127.0.0.1", port=8080):
        """
        The default constructor sets the server address to localhost:8080

        Assigns resources for queues, threads and addresses.
        """
        self.server_address = (ip, port)
        self.server_socket = None
        self.buffer_size = 4096
        self.queue = []
        self.thread = []
        self.addresses = {}

    def connect(self):
        """
        Creates a UDP socket and binds it to the address specified in the
        constructor.
        """
        try:
            self.server_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
            self.server_socket.bind(self.server_address)
            print(f"Server up and listening at {self.server_address[0]}:{self.server_address[1]}")
        except Exception as e:
            print("Socket not created.")
            print(e)
            sys.exit(1)
    
    def extract_header(self, string):
        """
        Extracts header from a string.
        Returns a dictionary containing header fields and their values

        For the header format, consult the design doc.
        """   
        header_list = re.findall(r"\$\*(.*)\*\$", string)[0].split(',')
        header = {}
        for i in header_list:
            spl = i.split(':')
            header[spl[0]] = spl[1]

        return header

    def timer(self, sec=3):
        """
        A function for a thread which runs for `sec` seconds and exits.
        """
        sleep(sec)
        return False
    
    def make_packet(self, string):
        """
        Adds a SHA-256 checksum to a packet of the required format.
        Returns the packet with a checksum.

        The checksum is over the entire string.
        """
        string = string[:2] + "checksum:," + string[2:]
        chksum = hashlib.sha256(string.encode()).hexdigest()
        string = string[:11] + chksum + string[11:]
        return string

    def check_packet(self, header, string):
        """
        Checks for corrupt packets.

        Checks if the packet minus the checksum has the same 
        checksum value as the checksum in the header field.
        """
        string = string[0:11] + string[75:]
        gen_chksum = hashlib.sha256(string.encode()).hexdigest()
        try:
            if header['checksum'] == gen_chksum:
                return True
            else:
                return False
        except KeyError:
            return False

    def service_worker(self, address, index):
        """
        This is a server which handles the client request.
        Implements the rdt protocol.

        This function runs in a separate thread and handles a single client
        specified by `address` and `index`. `index` is for the queue in the
        queue array.
        """
        msg = ""
        count = 0
        timed_send = None
        bytes_step = 450
        seq_no = 0
        expected_seq_no = seq_no + 1
        connected = False
        requested = False
        timeout = 3

        while True:
            if self.queue[index].empty() == False:
                count = 0
                

                data = self.queue[index].get()
                try:
                    header = self.extract_header(str(data))
                except KeyError:
                    self.server_socket.sendto(bytes(msg, 'UTF-8'), address)
                    timed_send = threading.Thread(target=self.timer, args=(timeout,), daemon=True)
                    timed_send.start()
                    continue
                
                corrupted = self.check_packet(header, str(data))
                print(header['purpose'], header['seqno'])
                if corrupted and connected:
                    self.server_socket.sendto(bytes(msg, 'UTF-8'), address)
                    timed_send = threading.Thread(target=self.timer, args=(timeout,), daemon=True)
                    timed_send.start()
                    continue

                if header['purpose'] == "SYN":
                    msg = f"$*seqno:{seq_no},purpose:ACK*$"
                    msg = self.make_packet(msg)
                    expected_seq_no = seq_no
                    seq_no += 1
                    self.server_socket.sendto(bytes(msg, 'UTF-8'), address)
                    timed_send = threading.Thread(target=self.timer, args=(timeout,), daemon=True)
                    timed_send.start()

                elif header['purpose'] == "SYN_ACK" and not connected:
                    connected = True
                    if int(header['seqno']) == expected_seq_no:
                        msg = f"$*seqno:{seq_no},purpose:ACK*$"
                        msg = self.make_packet(msg)
                        self.server_socket.sendto(bytes(msg, 'UTF-8'), address)
                        timed_send = threading.Thread(target=self.timer, args=(timeout,), daemon=True)
                        timed_send.start()
                    elif int(header['seqno']) == expected_seq_no-1:
                        self.server_socket.sendto(bytes(msg, 'UTF-8'), address)
                        timed_send = threading.Thread(target=self.timer, args=(timeout,), daemon=True)
                        timed_send.start()

                elif header['purpose'] == "REQ":
                    if requested == True:
                        continue
                    else:
                        requested = True
                    # extract filename
                    file_path = header['file']
                    try:
                        file = open(file_path, "rb")
                    except IOError:
                        seq_no += 1
                        expected_seq_no = seq_no
                        msg = f"$*seqno:{seq_no},purpose:INVFILE*$"
                        msg = self.make_packet(msg)
                        self.server_socket.sendto(bytes(msg, 'UTF-8'), address)
                        sleep(1)
                        sys.exit()
                    
                    file_data = str(file.read(bytes_step), encoding='UTF-8')
                    seq_no += 1
                    expected_seq_no = seq_no
                    msg = f"$*seqno:{seq_no},purpose:RESP*${file_data}"
                    msg = self.make_packet(msg)
                    self.server_socket.sendto(bytes(msg, 'UTF-8'), address)
                    start_time = time.time()
                    timed_send = threading.Thread(target=self.timer, args=(timeout,), daemon=True)
                    timed_send.start()

                elif header['purpose'] == "ACK":
                    if not requested:
                        continue
                    if int(header['seqno']) != expected_seq_no:
                        self.server_socket.sendto(bytes(msg, 'UTF-8'), address)
                        timed_send = threading.Thread(target=self.timer, args=(timeout,), daemon=True)
                        timed_send.start()
                    else:
                        loc = file.tell()
                        if file.read(bytes_step) == b"":
                            seq_no += 1
                            expected_seq_no = seq_no
                            msg = f"$*seqno:{seq_no},purpose:FILE_FIN*$"
                            msg = self.make_packet(msg)
                            self.server_socket.sendto(bytes(msg, 'UTF-8'), address)
                            end_time = time.time()
                            print(end_time-start_time)
                            timed_send = threading.Thread(target=self.timer, args=(timeout,), daemon=True)
                            timed_send.start()
                        else:
                            file.seek(loc, 0)
                            file_data = str(file.read(bytes_step),encoding='UTF-8')
                            
                            seq_no += 1
                            expected_seq_no = seq_no
                            msg = f"$*seqno:{seq_no},purpose:RESP*${file_data}"
                            msg = self.make_packet(msg)
                            self.server_socket.sendto(bytes(msg, 'UTF-8'), address)
                            timed_send = threading.Thread(target=self.timer, args=(timeout,), daemon=True)
                            timed_send.start()
                    
                elif header['purpose'] == "FIN_ACK":
                    if file:
                        file.close()
                    seq_no += 1
                    expected_seq_no = seq_no
                    msg = f"$*seqno:{seq_no},purpose:END*$"
                    msg = self.make_packet(msg)
                    self.server_socket.sendto(bytes(msg, 'UTF-8'), address)
                    sleep(1)
                    sys.exit(0)
                
                else:
                    self.server_socket.sendto(bytes(msg, 'UTF-8'), address)
                    timed_send = threading.Thread(target=self.timer, args=(timeout,), daemon=True)
                    timed_send.start()
            
            else:
                if timed_send.is_alive() == False:
                    # print(msg)
                    self.server_socket.sendto(bytes(msg, 'UTF-8'), address)
                    timed_send = threading.Thread(target=self.timer, args=(timeout,), daemon=True)
                    timed_send.start()

                    if count > 55:
                        if file:
                            file.close()
                        print("Connection ended.")
                        break
                    elif count == 50:
                        seq_no += 1
                        expected_seq_no = seq_no
                        msg = f"$*seqno:{seq_no},purpose:FIN*$"
                        msg = self.make_packet(msg)
                        print("No response from a long time. Exiting.")
                        count += 1
                    else:
                        count += 1
        
    def run(self):
        """
        Main loop of the server. Handles the received data and
        sends it to the appropriate service worker thread.
        """
        index = 0
        # Waiting
        while True:
            data, address = self.server_socket.recvfrom(self.buffer_size)
            # print(f"Recieved {len(data)} bytes from {address}")
            # print("Msg contents: ", data)

            try:
                header = self.extract_header(str(data))
            except KeyError:
                self.queue[self.addresses[address]].put(data)
                continue
            
            if header['purpose'] == 'SYN':
                if address not in self.addresses.keys():
                    q = Queue()
                    q.put(data)
                    self.queue.append(q)
                    self.addresses[address] = index
                    new_thread = threading.Thread(target=self.service_worker, args=(address, index))
                    self.thread.append(new_thread)
                    self.thread[index].start()
                    index += 1
            else:
                self.queue[self.addresses[address]].put(data)
            
        
        for i in self.thread:
            i.join()