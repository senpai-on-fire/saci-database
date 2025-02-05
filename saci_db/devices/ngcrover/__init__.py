import os
import networkx as nx
from clorm import Predicate, IntegerField

from saci.modeling.device.sensor import GPSReceiver, CompassSensor
from saci.modeling.device import Device, Motor, Servo, Controller, Wifi, Serial, PWMChannel, ESC, WebServer, WebClient
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
        pwm_channel_esc = PWMChannel()
        pwm_channel_servo = PWMChannel()
        motor = Motor()
        steering = Steering()
        uno_r3 = Controller()

        self.steering = steering

        components = [wifi, webserver, gps, compass, uno_r4, serial, uno_r3, pwm_channel_esc, pwm_channel_servo, esc, steering, motor,]

        component_graph = nx.from_edgelist([
            (wifi, webserver),
            (webserver, uno_r4),
            (gps, uno_r4),
            (compass, uno_r4),
            (serial, uno_r4),
            (uno_r4, uno_r3),
            (uno_r3, pwm_channel_esc),
            (uno_r3, pwm_channel_servo),
            (pwm_channel_esc, esc),
            (esc, motor),
            (pwm_channel_servo, steering),
        ], create_using=nx.DiGraph)

        entry_points = {
            wifi: True, 
            webserver: False,
            uno_r4: False,
            gps: True,
            compass: True,
            serial: True,
            uno_r3: False,
            pwm_channel_esc: False,
            esc: False,
            pwm_channel_servo: False,
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
