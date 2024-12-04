import os
import networkx as nx
from clorm import Predicate, IntegerField

from saci.modeling.device import Device, Motor, Controller
from saci.modeling.device.motor.steering import Steering
from saci.modeling.state import GlobalState

class QuadcopterCrash(Predicate):
    time = IntegerField()

class GSQuadcopter(Device):
    crash_atom = QuadcopterCrash
    description = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'device.lp')
    def __init__(self, state=None):

        stm32_mcu = Controller()
        # part of the firmware on the R4 is converting angle to PWM for servo
        motor = Motor()
        self.steering = steering = Steering()

        components = [stm32_mcu, motor, steering, ]

        component_graph=nx.from_edgelist([
            (stm32_mcu, motor),
            (stm32_mcu, steering),
            ], create_using=nx.DiGraph)

        entry_points = {
            stm32_mcu: True, 
            steering: False,
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
