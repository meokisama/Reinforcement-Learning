from __future__ import print_function

import array
import time
import numpy as np
from agent import QLearningTable

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib import snortlib
from ryu.lib import hub

checkMal = []
current_state = [1,0,0,0,0]
count_honeypot = 0
max_num = 0

class SimpleSwitchSnort(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'snortlib': snortlib.SnortLib}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchSnort, self).__init__(*args, **kwargs)
        self.snort = kwargs['snortlib']
        self.snort_port = 3
        self.mac_to_port = {}

        socket_config = {'unixsock': False}

        self.snort.set_config(socket_config)
        self.snort.start_socket_server()

        self.init_thread = hub.spawn(self._monitor)
        self.action_space = ['add', 'remove']
        self.n_actions = len(self.action_space)

    def packet_print(self, pkt):
        pkt = packet.Packet(array.array('B', pkt))

        eth = pkt.get_protocol(ethernet.ethernet)
        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        _icmp = pkt.get_protocol(icmp.icmp)

        if _icmp:
            self.logger.info("%r", _icmp)

        if _ipv4:
            self.logger.info("%r", _ipv4)

        if eth:
            self.logger.info("%r", eth)

        # for p in pkt.protocols:
        #     if hasattr(p, 'protocol_name') is False:
        #         break
        #     print('p: %s' % p.protocol_name)

    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _dump_alert(self, ev):
        msg = ev.msg
        global checkMal
        # print('alertmsg: %s' % ''.join(msg.alertmsg))

        checkMal.append(msg.alertmsg[0][:4])

        # self.packet_print(msg.pkt)
        
        global current_state, max_num
        if len(checkMal) == 20:
            if 'Ping' in checkMal:
                current_state[1] = 1
            if 'Mal02' in checkMal:
                current_state[2] = 2
            if 'Mal03' in checkMal:
                current_state[3] = 3
            if 'Mal04' in checkMal:
                current_state[4] = 4
            max_num = len(set(checkMal))
            checkMal = []
    
    def reset(self):
        return [1,0,0,0,0]

    def step(self, action):
        s = self.reset()
        global count_honeypot
        if action == 0:
            count_honeypot += 1
        elif action == 1:
            count_honeypot -= 1
        s_ = current_state
        # reward function
        if count_honeypot <= max_num:
            reward = 1
            done = True
            s_ = 'terminal'
        elif count_honeypot > max_num:
            reward = 0
            done = False

        return s_, reward, done
    
    def _monitor(self):
        print("Initializing...")
        hub.sleep(10)
        self.main()
                        
    def main(self):
        RL = QLearningTable(actions=list(range(self.n_actions)))

        for episode in range(100):
            # initial observation
            observation = self.reset()
            while True:
                # RL choose action based on observation
                action = RL.choose_action(str(observation))
                # RL take action and get next observation and reward
                observation_, reward, done = self.step(action)
                # RL learn from this transition
                RL.learn(str(observation), action, reward, str(observation_))
                # swap observation
                observation = observation_
                # break while loop when end of this episode
                if done:
                    break
        print("Number of Honeypots : ", count_honeypot)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port),
                   parser.OFPActionOutput(self.snort_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)