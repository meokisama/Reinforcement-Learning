import numpy as np
import time
import socket

HOST = "192.168.106.130"  # Standard loopback interface address (localhost)
PORT = 51234  # Port to listen on (non-privileged ports are > 1023)

checkMal = []
current_state = [1,0,0,0,0]
count_honeypot = 0
max_num = 0

class Maze(object):
    def __init__(self):
        super(Maze, self).__init__()
        self.action_space = ['add', 'remove']
        self.n_actions = len(self.action_space)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        global current_state, max_num
        with conn:
            print("Connected by ", addr)
            while True:
                data = conn.recv(65900)
                if not data:
                    break
                if data.decode('latin1')[:4] in ["Ping", "SMB"]:
                    attack_type = data.decode('latin1')[:4]

                checkMal.append(attack_type)

                if len(checkMal) == 20:
                    if 'Ping' in checkMal:
                        current_state[1] = 1
                    if 'SMB' in checkMal:
                        current_state[2] = 2
                    if 'Mal03' in checkMal:
                        current_state[3] = 3
                    if 'Mal04' in checkMal:
                        current_state[4] = 4
                    max_num = len(set(checkMal))
                    print("max num: ", max_num, "\nCheckMal: ", checkMal, "\nCurrent state: ", current_state)
                    checkMal = []
                    break

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
        if (count_honeypot <= max_num and count_honeypot > 0):
            reward = 1
            done = True
            s_ = 'terminal'
        elif (count_honeypot > max_num or count_honeypot < 0):
            reward = 0
            done = False
        print("Number of honeypots: ", count_honeypot)
        return s_, reward, done

    def render(self):
        time.sleep(0.1)