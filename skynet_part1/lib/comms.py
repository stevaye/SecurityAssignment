import struct
import base64

from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Random

from Crypto.Random import get_random_bytes
from Crypto import *

from dh import create_dh_key, calculate_dh_secret
from lib.crypto_utils import ANSI_X923_pad, ANSI_X923_unpad

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.key = None
        self.iv = None
        self.shared_hash = None
        self.initiate_session()
        

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret

        ### TODO: Your code here!
        # This can be broken into code run just on the server or just on the client
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(shared_hash))
            #self.key = shared_hash[16:].encode("ascii")
            #self.key = SHA256.new(self.key).hexdigest()[:16]
            self.shared_hash = shared_hash
            self.key = self.shared_hash[32:]
            print("SELF.KEY is: " + str(self.key))
            self.iv = self.shared_hash[16:]
            
            print("SELF.IV in INITIATE_SESSION is: " + str(self.iv))
            self.cipher = (self.key, AES.MODE_CBC, self.iv)


        # Default XOR algorithm can only take a key of length 32
        #self.cipher = XOR.new(shared_hash[:4])

    def send(self, data):
        # AES.block_size = 16
        #data = get_random_bytes(16) + data
        #iv = Random.new().read(AES.block_size) #IV is created for every time something is sent, so you cannot predict the outcome of the string
        #self.cipher = AES.new(self.key, AES.MODE_CBC, iv) ###self.key or just key?
        if type(data) != bytes:
           data = bytes(data, "ascii")


        if self.cipher:
            #self.iv = self.shared_hash[:16]
            #self.iv = Random.new().read(AES.block_size)
            #print("SELF.IV in SEND (First time it's been created): " + str(self.iv))
            self.iv = Random.get_random_bytes(16)
            self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv) ###self.key or just key? 
            padded_d = ANSI_X923_pad(data, AES.block_size)
            encrypted_data = self.iv + self.cipher.encrypt(padded_d)
            print("SELF.IV in SEND (After encrypted_data = self.iv + self.cipher.encrypt(data)) is: " + str(self.iv))

            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)

    def recv(self): #recieve strips the IV off either the end or front of the encrypted message (IV is 16 bits)
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]

        encrypted_data = self.conn.recv(pkt_len)
        if self.cipher:
            self.iv, encrypted_data = (encrypted_data[:16], encrypted_data[16:]) #Strips the prefixed IV from the encrypted data that is received
            self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv) ###self.key or just key?
            data = self.cipher.decrypt(encrypted_data)
            data = ANSI_X923_unpad(data, AES.block_size)
            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else:
            data = encrypted_data

        return data

    def close(self):
        self.conn.close()