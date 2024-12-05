import os
import networkx as nx
from clorm import Predicate, IntegerField

from saci.modeling.device import Device, Motor, Controller, Debug, Serial, ESC, SMBus, BMS, Battery
from saci.modeling.device.motor.steering import Steering
from saci.modeling.state import GlobalState

class QuadcopterCrash(Predicate):
    time = IntegerField()

class GSQuadcopter(Device):
    crash_atom = QuadcopterCrash
    description = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'device.lp')
    def __init__(self, state=None):

        debug = Debug()
        serial = Serial()
        esc = ESC()
        motor = Motor()
        smbus = SMBus()
        bms = BMS()
        battery = Battery()

        components = [debug, serial, esc, bms, smbus, motor, battery]

        component_graph=nx.from_edgelist([
            (serial, esc),
            (debug, esc),
            (esc, motor),
            (esc, bms),
            (smbus, bms),
            (bms, battery),
            (battery, esc),
            ], create_using=nx.DiGraph)

        entry_points = {
            serial: True, 
            debug: True,
            smbus: True,
            esc: False,
            bms: False,
            battery: False,
            motor: False
        }
        nx.set_node_attributes(component_graph, entry_points, 'is_entry')

        super().__init__(
        name="gs_quadcopter",
        components=components,
        component_graph=component_graph,
        state=state,
        #options=("has_aps",),
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
