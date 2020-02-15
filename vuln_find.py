from kivy.app import App
from kivy.uix.label import Label
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.behaviors import ButtonBehavior
from kivy.uix.gridlayout import GridLayout
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from functools import partial
from kivy.uix.widget import Widget
from kivy.properties import (
    NumericProperty, ReferenceListProperty, ObjectProperty
)
from kivy.uix.floatlayout import FloatLayout
from scrap import np_scan, srcap_vuln_info
import threading

class ButtonGrid(ButtonBehavior, GridLayout):

    def __init__(self, **kwargs):
        super(ButtonGrid, self).__init__(**kwargs)
        self.row_id = 0
        self.active = 0
        self.nm_param = []
    
    def select_grid(self):
        self.color = 1, 0, 0, 1

    def on_press(self):
        if (self.active):
            self.color = 0.93, 0.93, 0.93, 1
        else:
            self.color = 0.0, 0.68, 0.71, 1
        self.active = not self.active
        print("click on row %i" % self.row_id)

class   VulnFind(FloatLayout):

    def __init__(self, **kwargs):
        super(VulnFind, self).__init__(**kwargs)    

    def thread_scan(self, btn):
        ip, nm, ports = np_scan(self.target_scan.text, self.port_range.text)
        btn.disabled = False
        btn.text = "Scan"
        self.grid_scan.rows = len(ports) + 1
        for p in range(len(ports)):
            tmp_grid = ButtonGrid(cols=5, rows=1)
            tmp_grid.row_id = p
            tmp_grid.nm_param = ports[p]
            for i in range(len(ports[p])):
                label = Label(text=str(ports[p][i]).strip(),
                        color=self.convert_rgb(34, 40, 49))
                tmp_grid.add_widget(label)
            self.grid_scan.add_widget(tmp_grid)

    def clear_all(self):
        if (self.grid_scan.children):
            for c in self.grid_scan.children:
                self.grid_scan.remove_widget(c)

    def scan(self, btn):
        btn.disabled = True
        btn.text = "Scanning..."
        self.clear_all()
        func = threading.Thread(target=self.thread_scan, args=(btn, ))
        func.start()
    
    def convert_rgb(self, r, g, b):
        return round(r/255, 2), round(g/255, 2), round(b/255, 2), 1

    def thread_find(self, btn):
        for c in self.grid_scan.children:
            if c.active:
                srcap_vuln_info(*(c.nm_param[2::]))
        btn.disabled = False
        btn.text = "Find Exploit"

    def find_vuln(self, btn):
        btn.disabled = True
        btn.text = "Finding..."
        func = threading.Thread(target=self.thread_find, args=(btn, ))
        func.start()

    def vuln_info(self, btn):
        btn.background_color = 1, 0, 0.93, 1
        self.btn_about.background_color = 0.93, 0.93, 0.93, 1
        self.btn_port.background_color = 0.93, 0.93, 0.93, 1
        self.port_top.opacity = 0
        self.grid_scan.opacity = 0

    def port_info(self, btn):
        btn.background_color = 1, 0, 0.93, 1
        self.btn_about.background_color = 0.93, 0.93, 0.93, 1
        self.btn_vuln.background_color = 0.93, 0.93, 0.93, 1
        self.port_top.opacity = 1
        self.grid_scan.opacity = 1

    def about_info(self, btn):
        btn.background_color = 1, 0, 0.93, 1
        self.btn_vuln.background_color = 0.93, 0.93, 0.93, 1
        self.btn_port.background_color = 0.93, 0.93, 0.93, 1
        self.port_top.opacity = 0
        self.grid_scan.opacity = 0
                

class VulnFindApp(App):
    def build(self):
        app = VulnFind()
        return app

VulnFindApp().run()