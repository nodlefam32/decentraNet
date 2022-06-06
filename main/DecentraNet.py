import string
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
import socket
import random
import time
import os


class decentraNet:
    def __init__(self, IP, PORT, networkingDevice):
        self.IP = IP
        self.PORT = PORT
        self.pubKey = b''
        self.privKey = b''
        self.publicKeys = []
        self.ADDR = ('192.168.1.255', PORT)
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

        # Generate new key pair if one file does not exist
        if os.path.exists("private.key") and os.path.exists("public.key"):
            with open("private.key", "rb") as f:
                self.privKey = f.read()
                f.close()
            with open("public.key", "rb") as f:
                self.pubKey = f.read()
                f.close()
            print("Using old key delete private.key or public.key and run this program again to generate a new pair")
            print(f"{self.privKey}\n{self.pubKey}")
        else:
            keyPair = RSA.generate(1024, Random.new().read)  # Generate 2048-bit RSA keys must be broken for each user
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
        os.system(f"sudo iwconfig {networkingDevice} mode Ad-hoc")
        print("Set networking mode to Ad-hoc")
        os.system(f"sudo iwconfig {networkingDevice} essid TDN")
        print("Set networking essid to TDN")
        os.system(f"sudo ifconfig {networkingDevice} 192.168.1.1 netmask 255.255.255.0")
        print("Set IP to 192.168.1.1 and netmask to 255.255.255.0")
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

        """
        print("Waiting for response")

        startTime = time.time()
        while time.time() < startTime + 2.5:  # Aggressively receive responses for 2.5 seconds
            self.listen.setblocking(0)  # Keep letting those messages in don't wait for receives
            try:
                data, address = self.listen.recvfrom(16384)  # Accept responses; do not wait
                print(data, "\nAbove is my stupid response I received")
            except:
                pass
        self.listen.setblocking(1)  # Go back to waiting you sussy baka
        """

    def listenForDevices(self):
        os.system(f"sudo ifconfig {networkingDevice} 192.168.1.3 netmask 255.255.255.0")
        print("Listening for devices")
        while True:
            key, address = self.listen.recvfrom(16384)
            if not self.publicKeys.__contains__(key) and len(key) == 271 and key != self.pubKey:
                try:
                    publicKey = RSA.importKey(key)
                    publicKey = PKCS1_OAEP.new(publicKey)
                    lettersAvailable = string.ascii_letters + string.digits
                    sharedSecret = bytes(str(''.join(random.choice(lettersAvailable) for x in range(86))), 'utf-8')
                    print('your text before encryption is: {}'.format(sharedSecret))
                    encrypted_text = publicKey.encrypt(sharedSecret)
                    # rsa_private_key = RSA.importKey(self.privKey)
                    # rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
                    # decrypted_text = rsa_private_key.decrypt(encrypted_text)
                    # print(decrypted_text)

                    # print('your decrypted_text is: {}'.format(decrypted_text))
                    print(encrypted_text, len(encrypted_text))
                    self.publicKeys.append(key)
                    if len(self.publicKeys) > 16384:
                        self.publicKeys.remove(0)
                    print("received new key:", key)
                    os.system(f"sudo ifconfig {networkingDevice} 192.168.1.2 netmask 255.255.255.0")
                    for trialError in range(3):  # We loop 3 times to increase chances of discovering devices successfully
                        # Create socket for server
                        # Let's send data through UDP protocol
                        self.s.sendto(self.pubKey, self.ADDR)
                        print("Client Sent:", self.pubKey)
                except:
                    print("Invalid key received ignoring")


if __name__ == '__main__':
    IP = '192.168.1.1'
    PORT = 1050
    networkingDevice = 'eno1'
    while True:
        net = decentraNet(IP, PORT, networkingDevice)
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
