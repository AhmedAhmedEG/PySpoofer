if __name__ == "__main__":
    from multiprocessing import Pipe, Process, freeze_support
    freeze_support()
    from threading import Thread
    from netaddr import IPNetwork
    import sys
    from os.path import join
    from kivy.resources import resource_add_path, resource_find
    from kivy.config import Config
    from scapy.layers.inet import IP
    from scapy.layers.l2 import Ether
    from scapy.sendrecv import AsyncSniffer
    from lib.attacker import Attack
    from lib.scanner import Scanner
    from lib.gather import Gather

    Config.set('input', 'mouse', 'mouse,disable_multitouch')
    Config.set('graphics', 'minimum_width', '1020')
    Config.set('graphics', 'minimum_height', '521')
    Config.set('graphics', 'width', '1020')
    Config.set('graphics', 'height', '521')

    from kivy.app import App
    from kivy.uix.label import Label
    from kivy.clock import Clock
    from kivy.properties import ColorProperty, ListProperty, ObjectProperty, StringProperty, NumericProperty, BooleanProperty
    from kivy.uix.gridlayout import GridLayout
    from kivy.uix.widget import Widget
    from kivy.uix.button import Button
    from kivy.uix.textinput import TextInput
    from kivy.animation import Animation

    def animations(ins, anim):

        if anim == 0:
            Animation(width=950, t="out_expo").start(ins)
        elif anim == 1:
            Animation(height=53, t="in_bounce").start(ins)

    class FlatTextInput(TextInput):
        pass

    class TableBar(GridLayout):
        pass

    class FlatLabel(Label):
        radius = ListProperty([0, 0, 0, 0])
        background_color = ColorProperty([1, 1, 1, 1])

    class FlatButton(Button):
        radius = ListProperty([0, 0, 0, 0])
        mover = ObjectProperty(None)

        def stop(self):
            self.mover.cancel()
            self.text = self.text.strip(".")

        def move(self):
            self.mover = Clock.schedule_interval(self.loading, 0.5)

        def loading(self, timing):

            if self.text.count(".") == 3:
                self.text = self.text.strip(".")

            else:
                self.text = self.text + "."

    class FlatSwitch(Widget):

        ball_x = NumericProperty()
        active = BooleanProperty(True)
        back = ColorProperty([147/255, 147/255, 147/255])

        def __init__(self, **kwargs):
            super(FlatSwitch, self).__init__(**kwargs)
            self.register_event_type("on_press")

        def only_on(self):

            if self.active:
                self.dispatch('on_press')

        def on_press(self):
            self.disabled = True
            self.move()

            def disable(timing):
                self.disabled = False

            Clock.schedule_once(disable, 1)

        def move(self):

            if self.active:
                Animation(ball_x=self.x + self.width/5 + 28, t='out_expo').start(self)
                self.back = [75/255, 216/255, 101/255]
                self.active = False

            else:
                Animation(ball_x=self.x + self.width/5 + 5, t='out_expo').start(self)
                self.back = [147/255, 147/255, 147/255]
                self.active = True

        def on_touch_up(self, touch):

            if self.collide_point(*touch.pos) and touch.button == "left" and not self.disabled:
                self.dispatch('on_press')

    class HostController(GridLayout):
        ip = StringProperty("")
        mac = StringProperty("")
        name = StringProperty("")
        down_meter = ObjectProperty(None)
        down_limit = ObjectProperty(None)
        up_meter = ObjectProperty(None)
        up_limit = ObjectProperty(None)
        hccl = ObjectProperty(None)
        sfcl = ObjectProperty(None)
        attacker = ObjectProperty(None)
        app = ObjectProperty(None)
        attacker_args = ListProperty([])

        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            animations(self, 0)
            self.down_b, self.down_a = Pipe(duplex=False)
            self.up_b, self.up_a = Pipe(duplex=False)
            Thread(target=self.download_meter, daemon=True).start()
            Thread(target=self.upload_meter, daemon=True).start()

        def download_meter(self):

            while True:
                msg = self.down_b.recv()
                self.down_meter.text = msg

        def upload_meter(self):

            while True:
                msg = self.up_b.recv()
                self.up_meter.text = msg

        def spoof(self):

            if self.ip != "Disconnected":
                self.attacker_args[-1] = self.up_a
                self.attacker_args[-2] = self.down_a
                self.attacker_args[-5] = self.mac
                self.attacker_args[-6] = self.ip

                Process(target=Attack, args=tuple(self.attacker_args)).start()
                self.hccl.send("start")
                self.down_limit.dispatch('on_text_validate')
                self.up_limit.dispatch('on_text_validate')

                self.app.spoofed_mac_dict[self.mac] = self.ip # noqa
                self.app.spoofed_ip_dict[self.ip] = self.sfcl # noqa
                self.children[0].disabled = True
                self.children[1].disabled = False

                if not self.children[1].active:
                    self.children[1].dispatch('on_press')
                    self.children[1].dispatch('on_press')

        def un_spoof(self):
            self.hccl.send("stop")
            self.app.spoofed_ip_dict.pop(self.app.spoofed_mac_dict[self.mac]) # noqa
            self.app.spoofed_mac_dict.pop(self.mac) # noqa
            self.children[0].disabled = False
            self.children[1].disabled = True
            self.down_meter.text = "0 KB/s"
            self.up_meter.text = "0 KB/s"

        def save(self, text):
            lines = []
            found = False
            with open("config.txt", 'r+') as config:

                for l in config:
                    lines.append(l)

                for l in lines:
                    if self.mac in l:
                        lines[lines.index(l)] = f"{self.mac}|{text}"
                        found = True

                if not found:
                    lines.append(f"\n{self.mac}|{text}")

                config.truncate(0)
                config.seek(0)

                for l in lines:
                    config.write(l)

    class MainWindow(Widget):
        controllers_list = ObjectProperty(None)
        interface, gateway_ip, gateway_mac, my_ip, my_mac = Gather().get_info()

        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.mac_dict = {}
            self.ip_dict = {}
            self.spoofed_ip_dict = {}
            self.spoofed_mac_dict = {}
            self.filter_dict = {}
            self.hscl_b, self.hscl_a = Pipe(duplex=False)  # Host Scanner Communication Line
            self.b, self.a = Pipe(duplex=False)
            self.scanner_active = False
            self.load_filter_list()

            AsyncSniffer(prn=self.traffic_filter, filter=f"not ether proto arp and not host {self.my_ip}", iface=self.interface, store=0).start()

        def scan(self):
            Process(target=Scanner(self.interface, self.my_ip, self.gateway_ip, self.hscl_a, self.b).scan).start()
            Thread(target=self.scanner_receiver, daemon=True).start()
            self.scanner_active = True

        def scanner_receiver(self):

            #Conenction/Reconnection handling
            while True:
                msg = self.hscl_b.recv()

                if msg[0] in self.mac_dict:

                    if msg[1] == "dead":

                        if not self.mac_dict[msg[0]].children[2].active:
                            self.mac_dict[msg[0]].children[2].dispatch('on_press')

                        self.mac_dict.pop(msg[0])
                        self.ip_dict.pop(self.mac_dict[msg[0]].ip)
                        self.controllers_list.remove_widget(self.mac_dict[msg[0]])

                    elif msg[1] != self.mac_dict[msg[0]].ip:

                        if msg[1] in self.ip_dict:

                            if not self.ip_dict[msg[1]].children[2].active:
                                self.ip_dict[msg[1]].children[2].dispatch('on_press')

                            self.ip_dict[msg[1]].ip = "Disconnected"

                        self.ip_dict[msg[1]] = self.mac_dict[msg[0]]

                        if not self.mac_dict[msg[0]].children[2].active:
                            self.mac_dict[msg[0]].children[2].dispatch('on_press')
                            self.mac_dict[msg[0]].ip = msg[1]
                            self.mac_dict[msg[0]].children[2].dispatch('on_press')

                        else:
                            self.mac_dict[msg[0]].ip = msg[1]

                        # print("Reconnect check from loop 1 from " + msg[0])
                else:

                    if msg[1] in self.ip_dict:

                        if not self.ip_dict[msg[1]].children[2].active:
                            self.ip_dict[msg[1]].children[2].dispatch('on_press')

                        self.ip_dict[msg[1]].ip = "Disconnected"

                        # print("Reconnect check from loop 2 from " + msg[0])

                    sfcl_b, sfcl_a = Pipe(duplex=False)  # Sniffer's Filter Communication Line
                    hccl_b, hccl_a = Pipe(duplex=False)  # Host's Controller Communication Line

                    attacker_args = [self.interface, self.gateway_ip, self.gateway_mac, self.my_ip, self.my_mac, self.filter_dict, msg[1], msg[0], hccl_b, sfcl_b, None, None]
                    name = ""

                    with open("config.txt", 'r') as config:

                        for l in config:

                            if msg[0] in l:
                                name = l.split("|")[1]
                                break

                    host_controller = HostController(name=name, ip=msg[1], mac=msg[0], hccl=hccl_a, sfcl=sfcl_a, attacker_args=attacker_args, app=self)
                    self.mac_dict[msg[0]] = host_controller
                    self.ip_dict[msg[1]] = host_controller
                    self.controllers_list.add_widget(host_controller)

        def traffic_filter(self, packet):

            # The second condition is important if you want to use monitor mode
            if packet[Ether].src in self.spoofed_mac_dict and packet[Ether].dst == self.my_mac:
                msg = ["outbound", packet]
                self.spoofed_ip_dict[self.spoofed_mac_dict[packet[Ether].src]].send(msg)

            elif packet.haslayer(IP) and packet[IP].dst in self.spoofed_ip_dict and packet[Ether].dst == self.my_mac:
                msg = ["inbound", packet]
                self.spoofed_ip_dict[packet[IP].dst].send(msg)

        def load_filter_list(self):
            with open("Filter List.txt", 'r') as file:

                for line in file:

                    for ip in IPNetwork(line):
                        ip = str(ip).split(".")

                        if ip[0] in self.filter_dict:

                            if ip[1] in self.filter_dict[ip[0]]:

                                if ip[2] in self.filter_dict[ip[0]][ip[1]]:

                                    if ip[3] in self.filter_dict[ip[0]][ip[1]][ip[2]]:
                                        pass

                                    else:
                                        self.filter_dict[ip[0]][ip[1]][ip[2]].add(ip[3])

                                else:
                                    self.filter_dict[ip[0]][ip[1]][ip[2]] = set(ip[3])

                            else:
                                self.filter_dict[ip[0]][ip[1]] = {ip[2]: set(ip[3])}

                        else:
                            self.filter_dict[ip[0]] = {ip[1]: {ip[2]: set(ip[3])}}

    class PySpoofer(App):
        def build(self):
            self.title = 'PySpoofer V1.0'
            self.icon = "PySpoofer.png"
            return MainWindow()

    if hasattr(sys, '_MEIPASS'):
        resource_add_path(join(sys._MEIPASS)) # noqa

    PySpoofer().run()
