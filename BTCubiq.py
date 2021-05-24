from binascii import hexlify
import pygatt
import logging
import re
import lzstring
import argparse

import threading
import time

from kivy.app import App, Logger
from kivy.uix.widget import Widget
from kivy.lang import Builder
from kivy.factory import Factory
from kivy.animation import Animation
from kivy.clock import Clock, mainthread
from kivy.uix.gridlayout import GridLayout
from kivy.clock import Clock, CyClockBase
from kivy.properties import StringProperty

from kivy.base import ExceptionHandler, ExceptionManager

class CubeErrorHandler(ExceptionHandler):
    def handle_exception(self, inst):
        if isinstance(inst, ConnectionLostError):
            Logger.exception('Connection Lost Event Received! Resetting...')
            RootWidget.clear_BTCube()
            return ExceptionManager.PASS
        return ExceptionManager.RAISE



Builder.load_string( """

<RootWidget>:
    cols: 1

    canvas:
        Color:
            rgba: 0.9, 0.9, 0.9, 1
        Rectangle:
            pos: self.pos
            size: self.size

    but_1: but_1
    lab_2: lab_2

    Button:
        id: but_1
        font_size: 20
        text: 'Start Cube search'
        on_press: root.start_BTCube()

    Button:
        id: but_2
        font_size:20
        text: 'Reset Cube'
        on_press: root.clear_BTCube()

    Button:
        id: but_3
        font_size:20
        text: 'Clear moves'
        on_press: root.clear_moves()

    Label:
        id: lab_1
        font_size: 30
        color: 0.6, 0.6, 0.6, 1
        text_size: self.width, None
        halign: 'center'
        text: 'Label 1'

    Label:
        id: lab_2
        font_size: 10
        color: 0.6, 0.6, 0.6, 1
        text_Size: self.width/2, None
        halign: 'center' 
        text: 'Label 2'
    """)


class ConnectionLostError(Exception):

    def __init__(self, *args):
            if args:
                self.message = args[0]
            else:
                self.message = None

    def __str__(self):
        print('calling str')
        if self.message:
            return 'ConnectionLostException: {0}'.format(self.message)
        else:
            return 'ConnectionLostException raised'


class aes128:
    lastCount = -1
    key = None
    sbox = [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22]
    sboxI = [0]*256
    shiftTabI = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3]
    xtime = [0]*256

    def __init__(self, k):
        if sum(self.xtime) != 0:
            return

        for i in range(0,256):
            self.sboxI[self.sbox[i]] = i
        
        for i in range(0,128):
            self.xtime[i] = i << 1
            self.xtime[128 + i] = (i << 1) ^ 0x1b

        self.key = k
        exKey = self.key
        padding = 176-len(exKey)
        exKey = exKey + [0]*padding
        Rcon = 1
        for i in range(16,176,4):

            tmp = exKey[i - 4:i]

            if (i % 16 == 0):
                tmp = [self.sbox[tmp[1]] ^ Rcon, self.sbox[tmp[2]], self.sbox[tmp[3]], self.sbox[tmp[0]]]
                Rcon = self.xtime[Rcon]
            
            for j in range(0,4):
                exKey[i + j] = exKey[i + j - 16] ^ tmp[j]
    
        self.key = exKey

    def shiftSubAdd(self, state, rkey):
        state = state + [0]*(len(rkey) - len(state))
        state0 = list(state)
        
        for  i in range(0,16): 
            state[i] = self.sboxI[state0[self.shiftTabI[i]]] ^ rkey[i]

        return state
    
    
    def decrypt(self, block):
        rkey = self.key[160:176]
        block = block + [0]*(len(rkey)-len(block))
        for i in range(0,len(rkey)):
            block[i] ^= rkey[i]

        for i in range(144, 0, -16):
            block = self.shiftSubAdd(block, self.key[i:i + 16])
            for j in range(0,16,4):
                s0 = block[j + 0]
                s1 = block[j + 1]
                s2 = block[j + 2]
                s3 = block[j + 3]
                h = s0 ^ s1 ^ s2 ^ s3
                xh = self.xtime[h]
                h1 = self.xtime[self.xtime[xh ^ s0 ^ s2]] ^ h
                h2 = self.xtime[self.xtime[xh ^ s1 ^ s3]] ^ h
                block[j + 0] ^= h1 ^ self.xtime[s0 ^ s1]
                block[j + 1] ^= h2 ^ self.xtime[s1 ^ s2]
                block[j + 2] ^= h1 ^ self.xtime[s2 ^ s3]
                block[j + 3] ^= h2 ^ self.xtime[s3 ^ s0]
        
        block = self.shiftSubAdd(block, self.key[0:16])
        return block

    def decryptGan(self, data):
        decoded = [0]*len(data)
        for i in range (0, len(data)):
            decoded[i] = data[i]
    
        # decode the last 16 bytes first
        decode_temp = self.decrypt( decoded[len(decoded)-16:])

        # prepend the remainder
        if(len)(decoded)>16:
            decoded = decoded[0:len(decoded)-16] + decode_temp
            # decode (16 bytes) of this
            decoded = self.decrypt( decoded )
        
        return decoded

class BTCube:

    adapter = None
    cube_address = []
    found_devices = {}
    moves = []
    device = None
    gd = None
    adapter = None
    verbose = False
    c_version = None
    c_hwinfo = None
    c_cubestate = None
    c_battery = None
    errors = 0
    start_time = time.time()
    last_move_time = start_time

    GAN_UUID_SUFFIX = '-0000-1000-8000-00805f9b34fb'
    GAN_SERVICE_UUID_META = '0000180a' + GAN_UUID_SUFFIX
    GAN_CHRCT_VERSION = '00002a28' + GAN_UUID_SUFFIX
    GAN_CHRCT_HARDWARE = '00002a23' + GAN_UUID_SUFFIX
    GAN_SERVICE_UUID_DATA = '0000fff0' + GAN_UUID_SUFFIX
    GAN_CHRCT_CUBESTATE = '0000fff5' + GAN_UUID_SUFFIX # cube state, (54 - 6) facelets, 3 bit per facelet
    GAN_CHRCT_PREV_MOVES = '0000fff3' + GAN_UUID_SUFFIX # prev moves

    GAN_CHRCT_UUID_COUNTER = '0000fff6' + GAN_UUID_SUFFIX # move counter, time offsets between premoves
    GAN_CHRCT_UUID_BATTERY = '0000fff7' + GAN_UUID_SUFFIX

    GAN_ENCRYPTION_KEYS = [
        "NoRgnAHANATADDWJYwMxQOxiiEcfYgSK6Hpr4TYCs0IG1OEAbDszALpA",
        "NoNg7ANATFIQnARmogLBRUCs0oAYN8U5J45EQBmFADg0oJAOSlUQF0g"]  

    twists = ["U", "?", "U'", "R", "?", "R'", "F", "?", "F'", "D", "?", "D'", "L", "?", "L'", "B", "?", "B'"]
    

    @classmethod
    def clear(cls):

        if cls.adapter is not None:
            try:
                cls.adapter.stop()
            except Exception as e:
                print(e)
       
        c_hwinfo = None
        c_cubestate = None
        c_battery = None
        errors = 0
        start_time = time.time()
        cls.cube_address = []
        cls.found_devices = {}
        cls.moves = []
        cls.device = None
        cls.gd = None
        cls.adapter = None
        cls.verbose = False
        cls.c_version = None
        cls.c_hwinfo = None
        cls.c_cubestate = None
        cls.c_battery = None
        cls.start_time = time.time()
        cls.last_move_time = cls.start_time

    @classmethod
    def clearMoves(cls):
        cls.moves = []

    @classmethod
    def cube_callback(cls, devices, address, packet_type):
    
        stop_callback = False

        for d in devices.keys():
            dev = devices[d]
            if re.match("GAN", dev.name):
                print("Found {} - {} !! Connecting...".format(dev.name,dev.address))
                cls.cube_address = str(dev.address)
                print("cube_add - {}".format(cls.cube_address))
                stop_callback = True
                break
            if(dev.address in cls.found_devices.keys()):
                continue

            cls.found_devices[dev.address] = dev.name

            print("name {} - rssi {} - addr {} Added".format(dev.name, dev.rssi, dev.address))

        return stop_callback

    @classmethod
    def on_twist(cls,move):
        moveTime = time.time() - cls.start_time

        moveTimeDelta = moveTime - cls.last_move_time

        cls.moves.append([moveTimeDelta,move])

        cls.last_move_time = moveTime

        print("In Twist handler.. received {} at {}s".format(move,moveTime))


    ## process_gan_cubestate(data bytearray(), ganDecoder object
    ## Takes an initial encrypted cube state from the GAN. 
    ## Decrypt this 19 bit entry (first 16 bits, then prepend 
    ## the last 3 bits and rerun for first 16)
    @classmethod
    def process_gan_cubestate(cls, data, extra):
                
        if (cls.gd is not None):
            decoded = cls.gd.decryptGan(data)

            count = decoded[12]

            if (cls.gd.lastCount == -1):
                    cls.gd.lastCount = count

            if (count != cls.gd.lastCount):
                missed = (count - cls.gd.lastCount) & 0xff
                if (missed < 6):
                    cls.gd.lastCount = count
                    for  i in range(19 - missed,19):
                        t = decoded[i]
                        BTCube.on_twist(cls.twists[t])
    
    @classmethod
    def pollCube(cls,dt):
        try:
            cls.cube_data = cls.device.char_read(cls.GAN_CHRCT_CUBESTATE)
            cls.process_gan_cubestate(cls.cube_data,cls.gd)
        except Exception as e:
            print("Exception" + str(e))
            # Close the BT and clear. TODO: Find out explanation for timeouts
            cls.clear()
            raise ConnectionLostError(' Polling Timeout in pollCube ')
    
    @classmethod
    def getBattery(cls):
        try:
            c_battery   = cls.device.char_read(cls.GAN_CHRCT_UUID_BATTERY)
            decodedBattery = cls.gd.decryptGan(c_battery)
            if len(decodedBattery) > 7:
                cls.battery = decodedBattery[7]
        except Exception as e:
            print("Exception {}".format(e))

    @classmethod
    def getMoves(cls):
        moveString = ""
        for move in cls.moves:
             moveString = moveString + "{} {}".format(move[0],move[1])
        return moveString

    @classmethod
    def getMoveString(cls, line_space=.5):

        moveRetStr = ""

        #Append each move, change line if greater than .5s
        for move in cls.moves:
            moveStr = "{:1.3} {}".format(move[0],move[1] )
            if move[0] > line_space:
                moveRetStr = moveRetStr+"\n"+moveStr
            else:
                moveRetStr = moveRetStr+moveStr

        if moveRetStr == "":
            moveRetStr = "---";

        return moveRetStr

    @classmethod
    def run(cls):

        if len(cls.cube_address) != 0:
            return

        print("entering Run BTCUBE")

        if not cls.adapter:
            cls.adapter = pygatt.BGAPIBackend()

        cls.adapter.start()
        print ("Scanning for Cube...")
        cls.cubes = cls.adapter.scan(timeout=25,scan_window=150, scan_cb=cls.cube_callback)

        try:
            print("BTCube - Trying to connect")
            cls.device = cls.adapter.connect(cls.cube_address)
            print("BTCube - Trying to read characteristic -CubeState")
            c_cubestate = cls.device.char_read(cls.GAN_CHRCT_CUBESTATE)
            print("BTCube - Trying to read characteristics -Version")
            c_version   = cls.device.char_read(cls.GAN_CHRCT_VERSION)
            print("BTCube - Trying to read characteristics -HWInfo")
            c_hwinfo    = cls.device.char_read(cls.GAN_CHRCT_HARDWARE)
            
            cubestate = int.from_bytes(c_cubestate,byteorder="big")
            hwinfo =  int.from_bytes(c_hwinfo,byteorder="big")
            print("Cubestate Value: {0}".format(hex(cubestate)))
            print("Hardware Info: {}".format(hex(hwinfo)))
        except Exception as e:
            print(e)
            cls.adapter.stop()
            print("Bailing...")
            return      

        # Now set up encryption key
            # Grab the hw key (compressed with LZString) and decompress the 128 bit string
        version = c_version[0] << 16 | c_version[1] << 8  | c_version[2]
        # 65546 = 0
        keyind = version >> 8 & 0xff
        key = cls.GAN_ENCRYPTION_KEYS[keyind]
        key = lzstring.LZString().decompressFromEncodedURIComponent(key)
        key = [int(i) for i in key[1:len(key)-1].split(',')]
        for i in range(0,6):
            key[i] = (key[i]+c_hwinfo[5-i]) & 0xff
    
        cls.gd = aes128(key)

    

class RootWidget(GridLayout):
    cubeMoves = StringProperty()
    pollEvent = None
    cubeEvent = None

    def disconect(cls):
        cls.clear_BTCube()

    @mainthread
    def update_label_text(self, new_text):
        self.lab_2.text = new_text

    @mainthread
    def update_cube_state(self, *args):
        moves = BTCube.getMoveString()
        if moves is None:
            moves = "..."
        self.update_label_text(moves)

    @mainthread
    def clear_moves(self):
        self.lab_2.text = ""
        BTCube.clearMoves()

    def start_BTCube(self):
        threading.Thread(target=BTCube.run()).start()
        self.pollEvent = Clock.schedule_interval(BTCube.pollCube,.1)
        self.cubeEvent = Clock.schedule_interval(self.update_cube_state,.5)

    @classmethod 
    def clear_BTCube(cls):
        Clock.unschedule(cls.pollEvent)
        Clock.unschedule(cls.cubeEvent)
        BTCube.clear()



class ThreadedApp(App):

    def on_stop(self):
        # The Kivy event loop is about to stop, set a stop signal;
        # otherwise the app window will close, but the Python process will
        # keep running until all secondary threads exit.
        self.root.stop.set()

    def build(self):
        return RootWidget()

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='BTCubiq Usage:')
    parser.add_argument('--verbose', help='enable verbosity')
    args = parser.parse_args()
    BTCube.verbose = args.verbose
    ExceptionManager.add_handler(CubeErrorHandler())

    ThreadedApp().run()

 

  