from kivy.app import App
from kivy.uix.label import Label
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from functools import partial
from kivy.uix.widget import Widget
from kivy.properties import (
    NumericProperty, ReferenceListProperty, ObjectProperty
)
from kivy.uix.floatlayout import FloatLayout
from scrap import start_scan
import threading

class VulnFind(FloatLayout):
    target_scan = ObjectProperty(None)
    btn_scan = ObjectProperty(None)
    port_range = ObjectProperty(None)

    def thread_scan(self, btn):
        start_scan(self.target_scan.text, self.port_range.text)
        btn.disabled = False
        btn.text = "Scan"

    def scan(self, btn):
        btn.disabled = True
        btn.text = "Scanning..."
        func = threading.Thread(target=self.thread_scan, args=(btn, ))
        func.start()


class VulnFindApp(App):
    def build(self):
        app = VulnFind()
        return app

VulnFindApp().run()