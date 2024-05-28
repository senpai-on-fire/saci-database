import os
import networkx as nx
from clorm import Predicate, IntegerField

from saci.modeling.device import Device, MultiCopterMotorHigh, MultiCopterMotorAlgo, CyberComponentHigh
from saci.modeling.state import GlobalState

from .gcs_telemetry import GCSTelemetryHigh, GCSTelemetryAlgo
from .px4_controller import PX4ControllerHigh

class Drone_Crash(Predicate):
    time = IntegerField()

class PX4Quadcopter(Device):
    crash_atom = Drone_Crash
    description = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'device.lp')
    def __init__(self, state=None):
        super().__init__(
            name="px4_quadcopter_device",
            components=[
                GCSTelemetryHigh,
                GCSTelemetryAlgo,
                PX4ControllerHigh,
                MultiCopterMotorHigh,
                MultiCopterMotorAlgo
            ],
            component_graphs={
                CyberComponentHigh: nx.from_edgelist([
                    (GCSTelemetryHigh, PX4ControllerHigh),
                    (PX4ControllerHigh, MultiCopterMotorHigh),
                ], create_using=nx.DiGraph),
            },
            state=state,
        )

    def update_state(self, state: GlobalState) -> GlobalState:
        pass

