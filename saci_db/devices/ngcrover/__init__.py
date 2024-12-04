import os
import networkx as nx
from clorm import Predicate, IntegerField

from saci.modeling.device import Device, GPSReceiver, Motor, Controller, Wifi, Serial, ESC, WebServer
from saci.modeling.device.compass import CompassSensor
from saci.modeling.device.motor.steering import Steering
from saci.modeling.state import GlobalState


class RoverCrash(Predicate):
    time = IntegerField()

class NGCRover(Device):
    crash_atom = RoverCrash
    description = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'device.lp')
    def __init__(self, state=None):

        wifi = Wifi()
        serial = Serial()
        webserver = WebServer()
        gps = GPSReceiver() # sends NMEA messages to R4 over serial
        compass = CompassSensor() # reading two analog values
        uno_r4 = Controller()
        # part of the firmware on the R4 is converting angle to PWM for servo
        # r4 -> r3 over CAN
        esc = ESC()
        motor = Motor()
        steering = Steering()
        uno_r3 = Controller()

        self.steering = steering

        components = [wifi, webserver, gps, compass, uno_r4, serial, uno_r3, esc, steering, motor,]

        # Create the graph with edge list
        component_graph = nx.from_edgelist([
            (wifi, webserver),
            (webserver, uno_r4),
            (gps, uno_r4),
            (compass, uno_r4),
            (serial, uno_r4),
            (serial, uno_r3),
            (uno_r4, uno_r3),
            (uno_r3, esc),    
            (uno_r3, steering),
            (esc, motor),
            (steering, motor),
        ], create_using=nx.DiGraph)

        # Set node attributes with a dictionary
        entry_points = {
            wifi: True,  # wifi is an entry point
            webserver: False,
            uno_r4: False,
            gps: True,
            compass: True,
            serial: True,
            uno_r3: False,
            esc: False,
            steering: False,
            motor: False
        }
        nx.set_node_attributes(component_graph, entry_points, 'is_entry')

        super().__init__(
        name="ngc_rover",
        components=components,
        component_graph=component_graph,
        state=state,
        )

    def update_state(self, state: GlobalState) -> GlobalState:
        pass

    def get_option(self, name):
        match name:
            case "has_aps":
                return self.steering.has_aps

    def set_option(self, name, value):
        match name:
            case "has_aps":
                self.steering.has_aps = value
