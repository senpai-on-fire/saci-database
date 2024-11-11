import os
import networkx as nx
from clorm import Predicate, IntegerField

from saci.modeling.device import Device, MultiCopterMotorHigh, MultiCopterMotorAlgo, CyberComponentHigh, \
    MultiCopterMotor, TelemetryHigh, Controller, GPSReceiver, MotorHigh, ControllerHigh
from saci.modeling.device.compass import CompassSensorHigh
from saci.modeling.device.motor.steering import SteeringHigh
from saci.modeling.state import GlobalState

#from .gcs_telemetry import GCSTelemetryHigh, GCSTelemetryAlgo, GCSTelemetry
from saci.modeling.device import Telemetry, SikRadio, Mavlink
#from .px4_controller import PX4Controller
from .esp32s3 import ESP32S3WifiTelemetry

class RoverCrash(Predicate):
    time = IntegerField()

class NGCRover(Device):
    crash_atom = RoverCrash
    description = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'device.lp')
    def __init__(self, state=None):

        # wifi = ESP32S3WifiTelemetry()
        wifi = TelemetryHigh(protocol_name="wifi")
        gps = GPSReceiver() # sends NMEA messages to R4 over serial
        compass = CompassSensorHigh() # reading two analog values
        uno_r4 = ControllerHigh()
        # part of the firmware on the R4 is converting angle to PWM for servo
        # r4 -> r3 over CAN
        motor = MotorHigh()
        self.steering = steering = SteeringHigh()
        uno_r3 = ControllerHigh()

        components = [
            wifi, gps, compass, uno_r4, motor, steering, uno_r3
        ]

        super().__init__(
            name="ngc_rover",
            components=components,
            component_graph=nx.from_edgelist([
                (wifi, uno_r4),
                (gps, uno_r4),
                (compass, uno_r4),
                (uno_r4, uno_r3),
                (uno_r3, motor),
                (uno_r3, steering),
            ],
                create_using=nx.DiGraph),
            state=state,
            options=("has_aps",),
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
