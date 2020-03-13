import sys
import os
import enum
import socket


class TftpProcessor(object):
    """
    Implements logic for a TFTP client.
    The input to this object is a received UDP packet,
    the output is the packets to be written to the socket.
    This class MUST NOT know anything about the existing sockets
    its input and outputs are byte arrays ONLY.
    Store the output packets in a buffer (some list) in this class
    the function get_next_output_packet returns the first item in
    the packets to be sent.
    This class is also responsible for reading/writing files to the
    hard disk.
    Failing to comply with those requirements will invalidate
    your submission.
    Feel free to add more functions to this class as long as
    those functions don't interact with sockets nor inputs from
    user/sockets. For example, you can add functions that you
    think they are "private" only. Private functions in Python
    start with an "_", check the example below
    """

    class TftpPacketType(enum.Enum):
        """
        Represents a TFTP packet type add the missing types here and
        modify the existing values as necessary.
        """
        RRQ = 1


    def __init__(self):
        """
        Add and initialize the *internal* fields you need.
        Do NOT change the arguments passed to this function.
        Here's an example of what you can do inside this function.
        """
        self.packet_buffer = []
        self.file_name = ""
        pass

    def process_udp_packet(self, packet_data, packet_source):
        """
        Parse the input packet, execute your logic according to that packet.
        packet data is a bytearray, packet source contains the address
        information of the sender.
        """
        # Add your logic here, after your logic is done,
        # add the packet to be sent to self.packet_buffer
        # feel free to remove this line
        print(f"Received a packet from {packet_source}")

        in_packet = self._parse_udp_packet(packet_data)  # Check type of packet
        if in_packet == "DATA":  # Save the incoming data
            data_bytes = packet_data[4:len(packet_data)]
            data_bytes = bytes(data_bytes)
            f = open(self.file_name, "ab")
            f.write(data_bytes)
            f.close()

        out_packet = self._do_some_logic(in_packet)

        # This shouldn't change.
        self.packet_buffer.append(out_packet)

    def _parse_udp_packet(self, packet_bytes):
        if packet_bytes[1] == 3:
            return "DATA"
        elif packet_bytes[1] == 4:
            return "ACK"
        elif packet_bytes[1] == 4:
            if packet_bytes[3] == 0:
                print("ERROR: Not defined")
            elif packet_bytes[3] == 1:
                print("ERROR: File not found.")
            elif packet_bytes[3] == 2:
                print("ERROR: Access violation.")
            elif packet_bytes[3] == 3:
                print("ERROR: Disk full or allocation exceeded.")
            elif packet_bytes[3] == 4:
                print("ERROR: Illegal TFTP operation.")
            elif packet_bytes[3] == 5:
                print("ERROR: Unknown transfer ID.")
            elif packet_bytes[3] == 6:
                print("ERROR: File already exists.")
            elif packet_bytes[3] == 7:
                print("ERROR: No such user.")
            return "ERROR"
        pass

    def _do_some_logic(self, input_packet):
        """
        Example of a private function that does some logic.
        """
        pass

    def get_next_output_packet(self):
        """
        Returns the next packet that needs to be sent.
        This function returns a byetarray representing
        the next packet to be sent.
        For example;
        s_socket.send(tftp_processor.get_next_output_packet())
        Leave this function as is.
        """
        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):
        """
        Returns if any packets to be sent are available.
        Leave this function as is.
        """
        return len(self.packet_buffer) != 0

    def request_file(self, file_path_on_server):

        self.file_name = file_path_on_server
        f = open(file_path_on_server, "wb")  # Create initial file
        f.close()
        mode_bytes = "octet".encode()
        mode_bytes = list(mode_bytes)
        file_name_bytes = file_path_on_server.encode()
        file_name_bytes = list(file_name_bytes)

        # Create the RRQ byte array
        byte_array_rrq = bytearray([0, 1] + file_name_bytes + [0] + mode_bytes + [0])

        return byte_array_rrq

    def upload_file(self, file_path_on_server):

        mode_bytes = "octet".encode()
        file_name_bytes = file_path_on_server.encode()
        file_name_bytes = list(file_name_bytes)
        mode_bytes = list(mode_bytes)

        # Create the WRQ
        byte_array_wrq = bytearray([0, 2] + file_name_bytes + [0] + mode_bytes + [0])
        print("sending")
        print(byte_array_wrq)
        return byte_array_wrq


processor = TftpProcessor()


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def setup_sockets(address):
    """
    Socket logic MUST NOT be written in the TftpProcessor
    class. It knows nothing about the sockets.
    Feel free to delete this function.
    """
    pass


def do_socket_logic():
    """
    Example function for some helper logic, in case you
    want to be tidy and avoid stuffing the main function.
    Feel free to delete this function.
    """
    pass


def parse_user_input(address, operation, file_name=None):
    # Your socket logic can go here,
    # you can surely add new functions
    # to contain the socket code.
    # But don't add socket code in the TftpProcessor class.
    # Feel free to delete this code as long as the
    # functionality is preserved.
    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        byte_array = processor.upload_file(file_name)

        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.sendto(byte_array, (address, 69))
        data, server = udp_socket.recvfrom(4096)
        print('server: {!r}'.format(data))

        # Create the DATA packet byte array
        file_array = list(open(file_name, "rb").read())
        size_of_file = os.path.getsize(file_name)
        number_of_blocks = int(size_of_file / 512) + 1
        print("size is ")
        print(number_of_blocks)
        print(size_of_file)

        for x in range(1, number_of_blocks+1):

            block_no = list(x.to_bytes(2, 'big'))
            byte_array_data = bytearray([0, 3] + block_no + file_array)
            udp_socket.sendto(byte_array_data, server)
            data, server = udp_socket.recvfrom(4096)

        udp_socket.close()
        pass


    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        byte_array = processor.request_file(file_name)

        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.sendto(byte_array, (address, 69))

        while True:
            msg_from_server, server = udp_socket.recvfrom(1024)
            if not msg_from_server:
                break

            print(msg_from_server)
            msg_from_server = list(msg_from_server)
            byte_array_ack = bytearray([0, 4, msg_from_server[2], msg_from_server[3]])
            udp_socket.sendto(byte_array_ack, server)  # Send the Acknowledgment

            # Process the received packet
            processor.process_udp_packet(msg_from_server, address)

        udp_socket.close()

        pass


def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.
        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comamnd-line argument #[{param_index}] is missing")
            exit(-1)  # Program execution failed.


def main():
    """
        Write your code above this function.
       if you need the command line arguments
       """
    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    print("*" * 50)

    # This argument is required.
    # For a server, this means the IP that the server socket
    # will use.
    # The IP of the server, some default values
    # are provided. Feel free to modify them.
    ip_address = get_arg(1, "127.0.0.1")
    operation = get_arg(2, "push")
    file_name = get_arg(3, "file.txt")

    # Modify this as needed.
    parse_user_input(ip_address, operation, file_name)


if __name__ == "__main__":
    main()
