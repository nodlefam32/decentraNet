import string
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
from Crypto.Random import get_random_bytes
from base64 import b64encode
import socket
import random
import time
import os


class decentraNet:
    def __init__(self, anonymousMode, PORT, networkingDevice):
        self.PORT = PORT
        self.pubKey = b''
        self.privKey = b''
        self.publicKeys = []
        self.sharedSecrets = []
        self.anonymousMode = anonymousMode
        self.ADDR = ('192.168.1.255', PORT)
        self.mode = 1  # mode 1 = sending data, mode 2 = receiving data
        self.networkingDevice = networkingDevice
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.listen = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def generateKeys(self):

        # General introduction
        print("---Welcome to the decentralized IoT---")
        print("This builds emergency IoT infrastructure")
        print("This IoT allows you to access content as long as your device has a path to a target server")
        print("It is possible to be temporarily blocked from the IoT")
        print("This can also happen from an obstructed path but neither will compromise security")
        print("All communications are insecure")
        print("Never share your private key doing so will compromise the security of your device")
        print("Remember sites can be spoofed CHECK KEYS ALWAYS AND THIS DOES NOT GUARANTEE INTEGRITY")
        print("Checking for existence of private and public keys these are required to browse")
        print("To get a new identity delete the private and public key files.")

        # Read old pair if one does exist
        if os.path.exists("private.key") and os.path.exists("public.key") and self.anonymousMode is False:
            with open("private.key", "rb") as f:
                self.privKey = f.read()
                f.close()
            with open("public.key", "rb") as f:
                self.pubKey = f.read()
                f.close()
            print("Using old key delete private.key or public.key and run this program again to generate a new pair")
            print(f"{self.privKey}\n{self.pubKey}")
        else: # Generate new pair if one doesn't exist
            keyPair = RSA.generate(2048, Random.new().read)  # Generate unique 2048-bit RSA
            self.pubKey = keyPair.public_key().exportKey()
            self.privKey = keyPair.exportKey()

            with open("private.key", "wb") as f:
                f.write(self.privKey)
                f.close()

            with open("public.key", "wb") as f:
                f.write(self.pubKey)
                f.close()

            print("Created new key you now have a new identity")
            print(f"{self.privKey}\n{self.pubKey}")

    def configureNetworkDevice(self, networkingDevice):
        # Ad-hoc is only required for Wi-Fi
        os.system(f"sudo iwconfig {networkingDevice} mode Ad-hoc")
        print("Set networking mode to Ad-hoc")
        # essid is only required for Wi-Fi
        os.system(f"sudo iwconfig {networkingDevice} essid TDN")
        print("Set networking essid to TDN")
        os.system(f"sudo ifconfig {networkingDevice} 192.168.1.{self.mode} netmask 255.255.255.0")
        print(f"Set IP to 192.168.1.{self.mode} and netmask to 255.255.255.0")
        print("Finished device configuration")
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.listen.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.listen.bind(('', PORT))

    def searchForDevices(self):  # May be vulnerable but not RCE
        for trialError in range(3):  # We loop 3 times to increase chances of discovering devices successfully
            print("Broadcasted I am here~! {0}".format(trialError))

            # Let's send public key through UDP protocol
            self.s.sendto(self.pubKey, self.ADDR)
            print("Client Sent: ", self.pubKey)

    def listenForDevices(self):
        print("Listening for devices")
        while True:
            self.mode = 2
            os.system(f"sudo ifconfig {networkingDevice} 192.168.1.{self.mode} netmask 255.255.255.0")
            key, address = self.listen.recvfrom(16384)
            if not self.publicKeys.__contains__(key) and not key.__contains__(self.pubKey) and len(key) == 450:
                # Process new raw public key
                try:
                    # Verify the key received is real
                    publicKey = RSA.importKey(key)
                    publicKey = PKCS1_OAEP.new(publicKey)
                    sharedSecret = get_random_bytes(16 * 2)
                    encryptedSharedKey = publicKey.encrypt(sharedSecret)

                    print(encryptedSharedKey, len(encryptedSharedKey))
                    self.publicKeys.append(key)
                    self.sharedSecrets.append(sharedSecret)
                    if len(self.publicKeys) > 16384:
                        self.publicKeys.remove(0)
                        self.sharedSecrets.remove(0)
                    print("received new key:", key)
                    self.mode = 1
                    os.system(f"sudo ifconfig {networkingDevice} 192.168.1.{self.mode} netmask 255.255.255.0")
                    for trialError in range(3):  # We loop 3 times to increase chances of discovering devices successfully
                        # Create socket for server
                        # Let's send data through UDP protocol
                        self.s.sendto(self.pubKey + encryptedSharedKey, self.ADDR)  # Your public key and a shared key
                        print("Client Sent:", self.pubKey + encryptedSharedKey)
                except:
                    print("Invalid key received")
            elif not self.publicKeys.__contains__(key[0:450]) and not key.__contains__(self.pubKey) and len(key) > 450:
                try:
                    print("New key to process:", key)
                    IP = key[0:450]
                    secret = key[450:]
                    rsa_private_key = RSA.importKey(self.privKey)
                    rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
                    decryptedSharedKey = rsa_private_key.decrypt(secret)
                    self.publicKeys.append(IP)
                    self.sharedSecrets.append(decryptedSharedKey)
                    if len(self.publicKeys) > 16384:
                        self.publicKeys.remove(0)
                        self.sharedSecrets.remove(0)
                except:
                    print("Invalid key received")


if __name__ == '__main__':
    PORT = 1050
    anonymousMode = True
    networkingDevice = 'eno1'
    net = decentraNet(anonymousMode, PORT, networkingDevice)
    net.configureNetworkDevice(networkingDevice)
    net.generateKeys()
    net.searchForDevices()
    net.listenForDevices()
else:
    exit("You cannot import DecentraNet.")

"""
--- Decentralized mode ---
We start out by assigning ourselves the ip 192.168.1.1
We then configure the network card
We then scan the network for live devices
Bam we can use the network and access its services but remember to trade keys lol
"""

