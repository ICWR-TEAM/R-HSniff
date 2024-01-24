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

            if packet.haslayer(Raw) and packet.haslayer(TCP) and packet[TCP].dport == int(self.args.port):

                load = packet[Raw].load.decode(errors='ignore')

                http_method_match = re.search(r'(.*?)\s', load)
                http_method = http_method_match.group(1) if http_method_match else ''

                src = packet[IP].src

                dst_match = re.search(r'Host:\s+([^\r\n]+)', load)
                dst = dst_match.group(1) if dst_match else ''

                url_match = re.search(r'\s(.*?)\s', load)
                url = "http://{}{}".format(dst, url_match.group(1)) if url_match else ''

                data = re.search(r'\r\n\r\n(.+)', load, re.DOTALL)
                data = "[Data : {}]".format(data.group(1)) if data else ''
                # data = "[Data : {}]".format(str(data))

                headers = {}
                header_matches = re.finditer(r'([\w-]+):\s+([^\r\n]+)', load)

                for match in header_matches:

                    header_name = match.group(1)
                    header_value = match.group(2)
                    headers[header_name] = header_value

                output = "[+] [Request Packet]\r\n"
                output += "[+] [From : {}]\r\n".format(src)
                output += "[+] [Method : {}]\r\n".format(http_method)
                output += "[+] [URL : {}]\r\n".format(url)
                output += "[+] [Headers]\r\n"

                for header_name, header_value in headers.items():

                    output += "\t[{} : {}]\r\n".format(header_name, header_value)

                output += "[+] {}\r\n".format(data) if data else ''

                output += "[+] [End Packet]\r\n"

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
