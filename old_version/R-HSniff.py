print("""
 /$$$$$$$          /$$   /$$  /$$$$$$            /$$  /$$$$$$   /$$$$$$ 
| $$__  $$        | $$  | $$ /$$__  $$          |__/ /$$__  $$ /$$__  $$
| $$  \ $$        | $$  | $$| $$  \__/ /$$$$$$$  /$$| $$  \__/| $$  \__/
| $$$$$$$/ /$$$$$$| $$$$$$$$|  $$$$$$ | $$__  $$| $$| $$$$    | $$$$    
| $$__  $$|______/| $$__  $$ \____  $$| $$  \ $$| $$| $$_/    | $$_/    
| $$  \ $$        | $$  | $$ /$$  \ $$| $$  | $$| $$| $$      | $$      
| $$  | $$        | $$  | $$|  $$$$$$/| $$  | $$| $$| $$      | $$      
|__/  |__/        |__/  |__/ \______/ |__/  |__/|__/|__/      |__/      
========================================================================
[*] R-HSniff | HTTP Sniffer | Afrizal F.A - R&D ICWR
========================================================================                                                               
""")
from scapy.all import *
import re, argparse

class RSniff:

    def http_raw(self, packet):

        try:

            # if packet.haslayer(Raw) and packet.haslayer(TCP): # All PORT
            if packet.haslayer(Raw) and packet.haslayer(TCP) and packet[TCP].dport == int(self.args.port):

                load = packet[Raw].load.decode(errors='ignore')

                http_method = re.search(r'(.*?)\s', load).group(1)
                src = packet[IP].src
                # dst = packet[IP].dst
                dst = re.search(r'Host:\s+([^\r\n]+)', load).group(1) # Get From Header
                url = "http://{}{}".format(dst, re.search(r'\s(.*?)\s', load).group(1))
                data = re.search(r'\r\n\r\n(.+)', load, re.DOTALL)
                data = " [Data : {}]".format(data.group(1)) if data else ''

                output = "[+] [From : {}] [Method : {}] [URL : {}]{}".format(src, http_method, url, data)

                if ' http/' in load.lower():

                    print(output)

        except Exception as E:

            print("[-] [Error : {}]".format(E))

    def __init__(self):

        parser = argparse.ArgumentParser()
        parser.add_argument("-p", "--port", required = True, help = "For Setting HTTP PORT", type = int)
        self.args = parser.parse_args()

        print("[*] [Sniff Started]\n")

        sniff(prn=self.http_raw, store=0, filter="tcp port 80", iface=None)

RSniff() if __name__ == "__main__" else exit()
