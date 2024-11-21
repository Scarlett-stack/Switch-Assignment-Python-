#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

root_bridge_ID = 0
root_path_cost = 0
root_port = 0
def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def send_bdpu_every_sec(switch, interfaces):
    # Every 1 second:
    # if switch is root:
    #     Send BPDU on all trunk ports with:
    #         root_bridge_ID = own_bridge_ID
    #         sender_bridge_ID = own_bridge_ID
    #         sender_path_cost = 0
    print(f"DIN SEND BPDU EVERY SEC!! is root_bridge? {switch.is_root_bridge()}")
    while True:
        # tODO Send BDPU every second if necessary
        if switch.is_root_bridge():
            for interface in interfaces:
                vlan, state =  switch.ports.get(get_interface_name(interface), (None, None))
                if vlan == "T":
                    bpdu_packet = switch.build_bpdu(interface)
                    send_to_link(interface, len(bpdu_packet), bpdu_packet)
                
        time.sleep(1)

def read_switch_config(switch_id):
    #o sa folosesc un relative path pt ca probabil asta vrea checkeru
    config_file_path = f"./configs/switch{switch_id}.cfg"

    #salvam datele intr-o structura config , ma rog e un dex :)
    config ={"priority" : None, "interfaces" : {}}

    with open(config_file_path, 'r') as f:
        lines = f.readlines()

    config['priority'] = int(lines[0].strip())
    #acum luam si legaturile
    for line in lines[1:] :
        parts = line.strip().split() #scoatem spatiilw de la final si le separam dua spatiile din inauntru
        interface_name = parts[0]
        vlan = int(parts[1]) if parts[1] != "T" else "T" #crd ca trb int daca nu e trunk 
        config['interfaces'][interface_name] = vlan #dex in dex
    return config

class Frame:
    def __init__(self, source_addr, dest_addr,vlan_id, payload):
        self.source_addr = source_addr
        self.dest_addr = dest_addr
        self.vlan_tag = vlan_id
        self.payload = payload

class Switch:
    def __init__(self, config):
        self.priority = config.get("priority", None)
        self.ports = config.get("interfaces", {}) #in dex stocam starile porturilor/vlanurilor
        self.mac = get_switch_mac()  #asta nu mi-ammers idk
        self.mac_table = {} #si asta tot dex ii

    def display_port_states(self):
        for interface, (vlan, state) in self.ports.items():
            print(f"Interface {interface} is in state: {state} with vlan: {vlan}")
    
    def is_root_bridge(self):
        global root_bridge_ID
        return self.priority == root_bridge_ID

    def initialize_chestii(self, config):
        # Punem pe block-ing port-urile trunk pentru ca
        # doar de acolo pot aparea bucle. Port-urile catre
        # statii sunt pe deschise (e.g. designated)
        #items() le face lista de tupluri deci mai usor de parsat!
        for interface_name , vlan in config.get("interfaces", {}).items():
           # print(f"din init ineterface namr {interface_name} si vlan {vlan}")
            if vlan == 'T':
                self.ports[interface_name] = (vlan, 'BLOCKING')
            else:
                self.ports[interface_name] = (vlan, 'DESIGNATED')
        # In mod normal bridge ID este format si din switch.mac_address
        # pentru simplitate vom folosi doar priority value ce se gaseste in
        # configuratie
        global root_bridge_ID, root_path_cost
        root_bridge_ID = self.priority
        root_path_cost = 0
         # daca portul devine root bridge setam porturile ca designated
        if root_bridge_ID == self.priority:
            for interface in self.ports:
                self.ports[interface] = (self.ports[interface][0], 'DESIGNATED')

    def build_bpdu(self, port):
        dest_mac = b'\x01\x80\xC2\x00\x00\x00'
        # sa nu uit sa adaug src mac
        LLC_LENGTH = struct.pack('>H', 52)
        LLC_HEADER = b'\x42\x42\x03'
        FLAGS = b'\x00'
        BPDU_HEADER = struct.pack('>I', 0)
        root_bridge_id = struct.pack('>Q', root_bridge_ID)  # 8 bytes for root bridge ID as an integer
        root_path_COST = struct.pack('>I', root_path_cost)  # 4 bytes for root path cost as an integer
        own_bridge_ID = struct.pack('>Q', self.priority)  # 8 bytes for the switch's priority as integer
        PORT = struct.pack('>H', port)  # 2 bytes for port ID
        MESSAGE_AGE = struct.pack('>H', 1)  # 2 bytes for message age
        MAX_AGE = struct.pack('>H', 20) 
        HELLO_TIME = struct.pack('>H', 2)  
        FORWARD_DELAY = struct.pack('>H', 15)

        bpdu_package = (
        dest_mac +
        self.mac +
        LLC_LENGTH +
        LLC_HEADER +
        FLAGS +
        BPDU_HEADER +
        root_bridge_id +
        root_path_COST +
        own_bridge_ID +
        PORT +
        MESSAGE_AGE +
        MAX_AGE +
        HELLO_TIME +
        FORWARD_DELAY
        )
        return bpdu_package
        
    def receive_bpdu(self, bpdu_pack, incoming_port, interfaces):
        #print("RECV BPDU!!!")
        global root_bridge_ID, root_path_cost, root_port
        print(f"root_bridge_ID {root_bridge_ID}, root_path_cost {root_path_cost}, root_port: {root_port}")
        #bpdu pack e data din main!!
        bpdu_root_bridge_ID = int.from_bytes(bpdu_pack[22:30], 'big')
        bpdu_sender_path_cost = int.from_bytes(bpdu_pack[30:34], 'big')
        other_switch_id = int.from_bytes(bpdu_pack[34:42], 'big')

        print(f"din bpdu : bpdu_root_bgID {bpdu_root_bridge_ID}, sender path cost {bpdu_sender_path_cost}, otherswithc id {other_switch_id}")
        #continuam de aici sper sa reusim cu ajutorul lui Dumnezeu <3
        # if BPDU.root_bridge_ID < root_bridge_ID:
        # root_bridge_ID = BPDU.root_bridge_ID
        # # Vom adauga 10 la cost pentru ca toate link-urile sunt de 100 Mbps
        # root_path_cost = BPDU.sender_path_cost + 10 
        # root_port = port where BPDU was received
        if bpdu_root_bridge_ID < root_bridge_ID:

            print("AAA")
            root_path_cost = bpdu_sender_path_cost + 10
            root_port = incoming_port
        
            we_were_root = False
            if root_bridge_ID == self.priority:
                we_were_root = True
            print("were we root?", we_were_root)
            #  if we were the Root Bridge:
            #     set all interfaces not to hosts to blocking except the root port  
            if we_were_root == True:
                print("BBB")
                for interface in interfaces:
                    vlan, status = self.ports.get(get_interface_name(interface), (None, None))
                    print(f"--- VLAN: {vlan},  Status: {status}, port/interface {interface}") #ok???????
                    if interface != root_port and vlan == 'T':
                        self.ports[get_interface_name(interface)] = (vlan, 'BLOCKING')    
                    
            #self.display_port_states()
            # if root_port state is BLOCKING:
            #     Set root_port state to LISTENING

            root_bridge_ID = bpdu_root_bridge_ID
            vlan_root, status = self.ports.get(get_interface_name(root_port), (None, None))
            if status == 'BLOCKING':
                self.ports[get_interface_name(root_port)] = (vlan_root, 'LISTENING')
            # Update and forward this BPDU to all other trunk ports with:
            # sender_bridge_ID = own_bridge_ID
            # sender_path_cost = root_path_cost
            for interface in interfaces:
                if interface != incoming_port and self.ports[get_interface_name(interface)][0] == 'T' and self.ports[get_interface_name(interface)][1] != 'BLOCKING':
                    new_pack = bpdu_pack[0:30] + int(root_path_cost).to_bytes(4, 'big')  + int(self.priority).to_bytes(8,'big') + bpdu_pack[42:]
                    send_to_link(interface, len(new_pack), new_pack)
        
        #  Else if BPDU.root_bridge_ID == root_bridge_ID:
        # If port == root_port and BPDU.sender_path_cost + 10 < root_path_cost:
        #     root_path_cost = BPDU.sender_path_cost + 10
        elif bpdu_root_bridge_ID == root_bridge_ID:
           # print("CCC")
            if incoming_port == root_port and bpdu_sender_path_cost + 10 < root_path_cost:
                root_path_cost = bpdu_sender_path_cost + 10
            elif incoming_port != root_port:
                if bpdu_sender_path_cost > root_path_cost:
                    # if self.ports[get_interface_name(incoming_port)][1] != 'LISTENING':
                    vlan, status = self.ports[get_interface_name(incoming_port)]
                    self.ports[get_interface_name(incoming_port)] =(vlan, "DESIGNATED")
        #  Else if BPDU.sender_bridge_ID == own_bridge_ID:
        # Set port state to BLOCKING
        elif other_switch_id == self.priority:
            #print("DDD")
            vlan,  status = self.ports[get_interface_name(incoming_port)]
            self.ports[get_interface_name(incoming_port)] = (vlan, "BLOCKING")
        #else:
        #    return #asta e discard ?
        #  if own_bridge_ID == root_bridge_ID:
        # For each port on the bridge:
        #     Set port as DESIGNATED_PORT
        if self.priority == root_bridge_ID:
            for interface in interfaces:
                vlan,  status = self.ports[get_interface_name(interface)]
                self.ports[get_interface_name(interface)] = (vlan, "DESIGNATED")
        
        print("FINALE")
        self.display_port_states()
        #return
    
    def is_unicast(other_switchelf, dest_mac):
        #print("IS UNICATS OR NOT??")
       # print(dest_mac)
        first_byte = int(dest_mac[:2], 16)
        is_multicast = (first_byte & 0x01) != 0
        return not is_multicast
    
    def process_frame(self, frame, incoming_port, interfaces, vlan_id): #interfaces e din main
        
        if self.ports[get_interface_name(incoming_port)][1] == "BLOCKING":
            return
        src_mac = frame.source_addr
        dest_mac = frame.dest_addr

        self.mac_table[src_mac] = incoming_port #update mac tabela
        #print("vlan id: ", vlan_id)
        #print("IN P: si ce iese din interface name", get_interface_name(incoming_port))

        # in functie de portul sursa
        source_port_vlan, status = self.ports.get(get_interface_name(incoming_port), (None,None))
        #print("\n")
        #print("SOURCE VLAN incoming port", source_port_vlan, incoming_port)
        #cadrul are sau nu headerul ala deja!

        are_header = False
        # if (source_port_vlan == 'T'): 
        #     are_header = True
        #     frame_fara_header = frame.payload[0:12] + frame.payload[16:]
        frame_fara_tag = frame.payload[0:12] + frame.payload[16:]
        if vlan_id != -1:  #cadru primit de pe port trunk
            are_header = True
        else:
            vlan_id = source_port_vlan

        #print("are header? ", are_header)
        if (self.is_unicast(dest_mac)):
            #chiar daca e unicast tot trb sa verificam daca trimitem cu tagged frame
            if dest_mac in self.mac_table:
                #adica daca trimit pe trunk sau nu
                dest_port = self.mac_table[dest_mac]
                dest_vlan, dest_status =  self.ports.get(get_interface_name(dest_port), (None, None))
                print(f"*Destination VLAN: {dest_vlan}, Destination Status: {dest_status}, Destination port {dest_port}")
                #sper?

                #si daca e blocking mai trimit?
                # if dest_status == 'BLOCKING':
                #     return
                
                #acum verificam daca trb sa ii adaug header sau nu
                if dest_vlan == 'T':
                    if are_header == True:
                        #il trimit asa direct ig 
                        send_to_link(self.mac_table[dest_mac], len(frame.payload), frame.payload)
                    else: #trb adaugat eaderu
                        new_frame = frame.payload[0:12] + create_vlan_tag(vlan_id) + frame.payload[12:]
                        send_to_link(self.mac_table[dest_mac], len(new_frame), new_frame)
                else: #e trimis ppe un port access
                    if dest_vlan == vlan_id: #idk e conditia aia ciudata
                        if are_header == True:
                            send_to_link(self.mac_table[dest_mac], len(frame_fara_tag), frame_fara_tag)
                        else: #inseamnca ca tot de pe access a venit 
                            send_to_link(self.mac_table[dest_mac], len(frame.payload), frame.payload)

            else:
                #nu avem adresa in tabela => facem broadcast
                #dar si aici pastram logica!
                for port in interfaces: 
                    if port != incoming_port:
                        dest_vlan, status = self.ports.get(get_interface_name(port), (None, None))
                        print(f"** Destination VLAN: {dest_vlan}, Destination Status: {status}, Destination port {port}")

                        #daca e BLOCKING merg mai departe
                        # if status == 'BLOCKING':
                        #     continue
                        #daca il trimit pe trunk
                        #verific daca are header
                        #daca nu adaug
                        #altfel il trimit pe access
                        if dest_vlan == 'T':
                            if are_header == True:
                                send_to_link(port, len(frame.payload), frame.payload)
                            else: #nu are headeru dar ii trb ca trimit la trunk
                                new_frame = frame.payload[0:12] + create_vlan_tag(vlan_id) + frame.payload[12:]
                                send_to_link(port, len(new_frame), new_frame)
                        else: #vine de pe access 
                            if dest_vlan == vlan_id:
                                if are_header == True:
                                    send_to_link(port, len(frame_fara_tag), frame_fara_tag)
                                else:
                                    send_to_link(port, len(frame.payload), frame.payload)

        else:
            # e pe broadcast sigur
            # Atentie, acest broadcast va fi diferit in cazul in
            # care avem VLAN-uri
            # În cazul în care switch-ul folosește funcționalitatea de VLAN,
            # broadcast-ul o să se facă doar către porturile 
            # cu aceeași etichetă VLAN fie către porturile de tip trunk. 
           for port in interfaces: 
                if port != incoming_port:
                    #send_to_link(port, len(frame.payload), frame.payload)
                    dest_vlan, status = self.ports.get(get_interface_name(port), (None, None))
                    print(f"*** Destination VLAN: {dest_vlan}, Destination Status: {status}, Dest port {port}")

                    #daca e BLOCKING merg mai departe
                    # if status == 'BLOCKING':
                    #     continue
                    #daca il trimit pe trunk
                    #verific daca are header
                    #daca nu adaug
                    #altfel il trimit pe access
                    if dest_vlan == 'T':
                        if are_header == True:
                            send_to_link(port, len(frame.payload), frame.payload)
                        else: #nu are headeru dar ii trb ca trimit la trunk
                            new_frame = frame.payload[0:12] + create_vlan_tag(vlan_id) + frame.payload[12:]
                            send_to_link(port, len(new_frame), new_frame)
                    else: #vine de pe access 
                        if dest_vlan == vlan_id:  #e o problema aici
                            if are_header == True:
                                send_to_link(port, len(frame_fara_tag), frame_fara_tag)
                            else:
                                send_to_link(port, len(frame.payload), frame.payload)

    #### FUNCTIA BASIC DE PROCESS FRAME -- MERGE PT PRIMUL SET DE TESTE DECI DE LA MINE E PROBLEMA! ####
    # def process_frame(self, frame, incoming_port, interfaces, vlan_id): #interfaces e din main
    #     src_mac = frame.source_addr
    #     dest_mac = frame.dest_addr

    #     self.mac_table[src_mac] = incoming_port #update mac tabela
    #     # in functie de portul sursa
    #     #source_port_vlan = self. 
    #     if (self.is_unicast(dest_mac)):
    #         if dest_mac in self.mac_table:
    #             send_to_link(self.mac_table[dest_mac], len(frame.payload), frame.payload)
    #         else:
    #             for port in interfaces: 
    #                 if port != incoming_port:
    #                     send_to_link(port, len(frame.payload), frame.payload)

    #     else:
    #         # e pe broadcast sigur
    #         # Atentie, acest broadcast va fi diferit in cazul in
    #         # care avem VLAN-uri
    #         # În cazul în care switch-ul folosește funcționalitatea de VLAN,
    #         # broadcast-ul o să se facă doar către porturile 
    #         # cu aceeași etichetă VLAN fie către porturile de tip trunk. 
    #        for port in interfaces: 
    #             if port != incoming_port:
    #                 send_to_link(port, len(frame.payload), frame.payload)

def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])


    interfaces = range(0, num_interfaces)

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    switch_conf = read_switch_config(switch_id)
    #acum facem functia de initialize!
    #de fapt o sa facem o clasa ca e mai usor
   # mac = get_interface_name(switch_id)
    switch = Switch(config=switch_conf)
    switch.initialize_chestii(switch_conf)

    print("STARILE SWITCHULUI :")
    switch.display_port_states()
    print("\n")
    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=lambda: send_bdpu_every_sec(switch=switch, interfaces=interfaces))
    t.start()

    # Printing interface names
    # for i in interfaces:
    #     print(get_interface_name(i))

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        #print(f'Destination MAC: {dest_mac}')
        #print(f'Source MAC: {src_mac}')
        #print(f'EtherType: {ethertype}')

        #print("Received frame of size {} on interface {}".format(length, interface), flush=True)
        #T$ODO: Implement STP support

        #mai intai trb verifcat daca am primit ceva pe adresa aia multicast 
        #daca da ar trb sa fac stp 

        if dest_mac == "01:80:c2:00:00:00":
            switch.receive_bpdu(data,interface, interfaces)
        else:
        # T#ODO: Implement forwarding with learning
        # T#ODO: Implement VLAN support
            frame = Frame(source_addr=src_mac, dest_addr=dest_mac,vlan_id=vlan_id, payload=data) #e nevoie intreaga!!! cad rescriu pt vlan
            switch.process_frame(frame=frame, incoming_port=interface, interfaces=interfaces, vlan_id=vlan_id)
        
        

        # data is of type bytes.
        # send_to_link(i, length, data)

if __name__ == "__main__":
    main()