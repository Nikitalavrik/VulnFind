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
from scrap import np_scan
import threading

class ButtonGrid(ButtonBehavior, GridLayout):

    def __init__(self, **kwargs):
        super(ButtonGrid, self).__init__(**kwargs)
        self.row_id = 0
    
    def on_press(self):
        print("click on row %i" % self.row_id)

class   VulnFind(FloatLayout):
    scan_box = ObjectProperty(None)
    target_scan = ObjectProperty(None)
    btn_scan = ObjectProperty(None)
    port_range = ObjectProperty(None)
    grid_scan = ObjectProperty(None)
    # scan_box.size = 100, 100

    def thread_scan(self, btn):
        ports = np_scan(self.target_scan.text, self.port_range.text)
        btn.disabled = False
        btn.text = "Scan"
        self.grid_scan.rows = len(ports) + 1
        for p in range(len(ports)):
            tmp_grid = ButtonGrid(cols=5, rows=1)
            tmp_grid.row_id = p
            for i in ports[p]:
                tmp_grid.add_widget(Label(text=str(i).strip(), 
                            color=self.convert_rgb(34, 40, 49)))
            self.grid_scan.add_widget(tmp_grid)

    def scan(self, btn):
        btn.disabled = True
        btn.text = "Scanning..."
        func = threading.Thread(target=self.thread_scan, args=(btn, ))
        func.start()
    
    def convert_rgb(self, r, g, b):
        return r/255, g/255, b/255, 1


class VulnFindApp(App):
    def build(self):
        app = VulnFind()
        return app

VulnFindApp().run()