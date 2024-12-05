import os
import networkx as nx
from clorm import Predicate, IntegerField
from saci.modeling.state import GlobalState

from .gcs_telemetry import GCSTelemetry
from saci.modeling.device import Device, MultiCopterMotor, ESC, SikRadio, Mavlink, GPSReceiver

from .px4_controller import PX4Controller

class Drone_Crash(Predicate):
    time = IntegerField()

class PX4Quadcopter(Device):
    crash_atom = Drone_Crash
    description = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'device.lp')
    def __init__(self, state=None):

        gcs = GCSTelemetry(has_external_input=True)
        sik = SikRadio()
        mavlink = Mavlink()
        #icmp = ICMP()
        gps = GPSReceiver() # sends NMEA messages to R4 over serial
        px4_cont = PX4Controller()
        esc = ESC()
        motor = MultiCopterMotor()

        components = [gcs, sik, mavlink, px4_cont, motor,]

        component_graph=nx.from_edgelist([
            (gcs, sik),
            (gcs, mavlink),
            #(gcs, icmp),
            (gps, px4_cont),
            (sik, px4_cont),
            (mavlink, px4_cont),
            (px4_cont, esc),
            (esc, motor),
        ],
        create_using=nx.DiGraph)

        entry_points = {
            gcs: True, 
            gps: True,
            sik: False,
            mavlink: False,
            px4_cont: False,
            motor: False
        }
        nx.set_node_attributes(component_graph, entry_points, 'is_entry')

        super().__init__(
        name="px4_quadcopter_device",
        components=components,
        component_graph=component_graph,
        state=state,
        )

    def update_state(self, state: GlobalState) -> GlobalState:
        pass

