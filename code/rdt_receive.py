import hashlib
import socket
import re
import sys
import threading
import time


class Client:
    """
    A class to implement the client part of rdt protocol
    """

    def __init__(self, ip, port, filename):
        """
        Creates resources and defines variables for the client implementation

        `filename` is the file path of the requested file on the server.
        """

        self.server_address = (ip, port)
        self.requested_file = filename
        self.buffer_size = 4096
        self.receive_socket = None
        self.seq_no = 0
        self.expected_seq_no = 0
        self.msg = ""
        self.terminate = False
        self.syn_terminate = False
        self.timeout = False

    def create_socket(self):
        """
        Creates a UDP socket.
        """

        try:
            self.receive_socket = socket.socket(
                family=socket.AF_INET, type=socket.SOCK_DGRAM
            )
            print("Socket Created.")
            return True
        except Exception as e:
            print("An exception occured while connecting to the server.")
            print(e)
            print("Socket creation unsuccessful")
            print("Exiting")
            return False

    def extract_header(self, string):
        """
        Extracts header from a string.
        Returns a dictionary containing header fields and their values

        For the header format, consult the design doc.
        """ 

        header_list = re.findall(r"\$\*(.*)\*\$", string)[0].split(",")
        header = {}
        for i in header_list:
            spl = i.split(":")
            header[spl[0]] = spl[1]

        return header

    def extract_data(self, string):
        data = string[(string.find("*$") + 2) :]
        return data

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
            if header["checksum"] == gen_chksum:
                return True
            else:
                return False
        except KeyError:
            return False

    def timer(self, message, address, syn=False, count=3):
        syn_term_count = 0
        # print(syn)
        while True:
            if syn_term_count == 30:
                self.timeout = True
                print("Connection unsuccessful.")
                sys.exit(1)
            if syn:
                if self.syn_terminate:
                    sys.exit()
                syn_term_count += 1
                # print(syn_term_count)
            else:
                if self.terminate == True:
                    sys.exit()

            self.receive_socket.sendto(bytes(message, "UTF-8"), address)
            time.sleep(count)
        return False

    def receive(self):
        print("Trying to connect...")
        msg = "$*seqno:0,purpose:SYN*$"
        msg = self.make_packet(msg)
        recvd = False
        network_congested = False
        self.receive_socket.settimeout(90)

        # Send SYN packets
        while recvd == False:
            timed_send = threading.Thread(
                target=self.timer, args=(msg, self.server_address, True), daemon=True
            )
            timed_send.start()
            while True:
                try:
                    resp = self.receive_socket.recvfrom(self.buffer_size)
                    break
                except socket.timeout:
                    if not timed_send.is_alive():
                        sys.exit()
            # self.receive_socket.settimeout(None)

            # Corrupt check
            header = self.extract_header(str(resp[0]))
            corrupted = self.check_packet(header, str(resp[0]))
            if not corrupted:
                self.terminate = True
                self.syn_terminate = True

                # If ACK is recvd
                if "ACK" in str(resp[0]):
                    recvd = True
                else:
                    print("Server says:", str(resp[0]))
                    print("Exiting.")
                    sys.exit()

        if recvd == True:

            if header["purpose"] == "ACK":
                self.seq_no = int(header["seqno"])
                self.expected_seq_no = self.seq_no + 1

                msg = f"$*seqno:{self.seq_no},purpose:SYN_ACK*$"
                msg = self.make_packet(msg)
                while True:
                    self.terminate = False
                    timed_send = threading.Thread(
                        target=self.timer, args=(msg, self.server_address), daemon=True
                    )
                    timed_send.start()
                    
                    try:
                        resp = self.receive_socket.recvfrom(self.buffer_size)
                    except socket.timeout:
                        if not timed_send.is_alive():
                            sys.exit()
                    
                    # Corrupt check
                    header = self.extract_header(str(resp[0]))
                    corrupted = self.check_packet(header, str(resp[0]))
                    if not corrupted:
                        self.terminate = True

                        if (
                            header["purpose"] == "ACK"
                            and int(header["seqno"]) == self.expected_seq_no
                        ):
                            self.seq_no = self.expected_seq_no
                            self.expected_seq_no += 1
                            break

        print("Connected.")
        # Now we are connected. Send REQuest
        msg = f"$*seqno:{self.seq_no},purpose:REQ,file:{self.requested_file}*$"
        msg = self.make_packet(msg)
        # self.terminate = False
        self.syn_terminate = False
        timed_send = threading.Thread(
            target=self.timer, args=(msg, self.server_address, True), daemon=True
        )
        timed_send.start()
        # Is the next packet the first response?
        first_packet = True
        count = 0
        file = None
        self.receive_socket.settimeout(90)

        while True:
            # Receive RESPonse
            if count == 10:
                print("Exiting.")
                sys.exit(1)
            if network_congested:
                count += 1

            try:
                resp = self.receive_socket.recvfrom(self.buffer_size)
            except socket.timeout:
                print("No response from a long time. Exiting.")
                if file:
                    file.close()
                sys.exit(1)

            header = self.extract_header(str(resp[0]))
            corrupted = self.check_packet(header, str(resp[0]))

            if corrupted and not network_congested:
                self.receive_socket.sendto(bytes(msg, "UTF-8"), self.server_address)
                continue

            if header["purpose"] == "RESP":
                # Send ACK
                self.terminate = True
                if first_packet == True:
                    self.syn_terminate = True
                    first_packet = False
                    try:
                        # file = open(self.requested_file, "wb")
                        file = open("client_test.txt", "wb")
                    except IOError as e:
                        print("Some IO Error occured. Exiting.")
                        print(e)
                        sys.exit(1)
                if int(header["seqno"]) == self.expected_seq_no:

                    # Deliver data
                    data = self.extract_data(str(resp[0], encoding="UTF-8"))
                    file.write(bytes(data, encoding="UTF-8"))
                    # print(data)
                    print(header["purpose"], header["seqno"])

                    # Send ACK
                    self.seq_no = self.expected_seq_no
                    self.expected_seq_no += 1
                    msg = f"$*seqno:{self.seq_no},purpose:ACK*$"
                    msg = self.make_packet(msg)
                    self.receive_socket.sendto(bytes(msg, "UTF-8"), self.server_address)
                else:
                    if first_packet:
                        msg = f"$*seqno:{self.seq_no},purpose:REQ,file:hello.py*$"
                        msg = self.make_packet(msg)
                        self.receive_socket.sendto(
                            bytes(msg, "UTF-8"), self.server_address
                        )
                    else:
                        # Send ACK of seq_no.
                        msg = f"$*seqno:{self.seq_no},purpose:ACK*$"
                        msg = self.make_packet(msg)
                        self.receive_socket.sendto(
                            bytes(msg, "UTF-8"), self.server_address
                        )

            elif header["purpose"] == "INVFILE":
                print("Requested file does not exist")
                sys.exit(1)

            elif header["purpose"] == "CONG":
                network_congested = True
                print("Network congested. Please try again later.")
                msg = f"$*seqno:{self.seq_no},purpose:CONG_ACK*$"
                msg = self.make_packet(msg)
                self.terminate = False
                timed_send = threading.Thread(
                    target=self.timer,
                    args=(msg, self.server_address, True),
                    daemon=True,
                )
                timed_send.start()
                if file != None:
                    file.close()

            elif header["purpose"] == "FILE_FIN":
                # Send FIN_ACK
                if file != None:
                    file.close()
                self.seq_no = self.expected_seq_no
                self.expected_seq_no += 1
                fin_msg = f"$*seqno:{self.seq_no},purpose:FIN_ACK*$"
                msg = self.make_packet(msg)
                self.receive_socket.sendto(bytes(fin_msg, "UTF-8"), self.server_address)
                print("Done!")
                break

            elif header["purpose"] == "FIN":
                # Send FIN_ACK
                if file != None:
                    file.close()
                self.seq_no = self.expected_seq_no
                self.expected_seq_no += 1
                fin_msg = f"$*seqno:{self.seq_no},purpose:FIN_ACK*$"
                msg = self.make_packet(msg)
                self.receive_socket.sendto(bytes(fin_msg, "UTF-8"), self.server_address)
                print("File transfer unsuccessful. The network may be congested.")
                print("Please try again later.")
                break
