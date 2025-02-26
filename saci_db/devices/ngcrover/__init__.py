import os
import networkx as nx
from clorm import Predicate, IntegerField

from saci.modeling.device.sensor import GPSReceiver, CompassSensor
from saci.modeling.device import ComponentID, Device, Motor, Servo, Controller, Wifi, Serial, PWMChannel, ESC, WebServer, WebClient
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

        components = { ComponentID('wifi'): wifi, ComponentID('webserver'): webserver, ComponentID('gps'): gps, ComponentID('compass'): compass, ComponentID('uno_r4'): uno_r4, ComponentID('serial'): serial, ComponentID('uno_r3'): uno_r3, ComponentID('pwm_channel_esc'): pwm_channel_esc, ComponentID('pwm_channel_servo'): pwm_channel_servo, ComponentID('esc'): esc, ComponentID('steering'): steering, ComponentID('motor'): motor, }

        component_graph = nx.from_edgelist([(ComponentID('wifi'), ComponentID('webserver')),
        (ComponentID('webserver'), ComponentID('uno_r4')),
        (ComponentID('gps'), ComponentID('uno_r4')),
        (ComponentID('compass'), ComponentID('uno_r4')),
        (ComponentID('serial'), ComponentID('uno_r4')),
        (ComponentID('uno_r4'), ComponentID('uno_r3')),
        (ComponentID('uno_r3'), ComponentID('pwm_channel_esc')),
        (ComponentID('uno_r3'), ComponentID('pwm_channel_servo')),
        (ComponentID('pwm_channel_esc'), ComponentID('esc')),
        (ComponentID('esc'), ComponentID('motor')),
        (ComponentID('pwm_channel_servo'), ComponentID('steering')),], create_using=nx.DiGraph)

        entry_points = {
            ComponentID('wifi'): True, 
            ComponentID('webserver'): False,
            ComponentID('uno_r4'): False,
            ComponentID('gps'): True,
            ComponentID('compass'): True,
            ComponentID('serial'): True,
            ComponentID('uno_r3'): False,
            ComponentID('pwm_channel_esc'): False,
            ComponentID('esc'): False,
            ComponentID('pwm_channel_servo'): False,
            ComponentID('steering'): False,
            ComponentID('motor'): False
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
