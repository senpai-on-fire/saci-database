import os
import networkx as nx
from clorm import Predicate, IntegerField

from saci.modeling.device import Device, MultiCopterMotorHigh, MultiCopterMotorAlgo, CyberComponentHigh, MultiCopterMotor
from saci.modeling.state import GlobalState

from .gcs_telemetry import GCSTelemetryHigh, GCSTelemetryAlgo, GCSTelemetry
from saci.modeling.device import Telemetry, SikRadio, Mavlink
from .px4_controller import PX4ControllerHigh

class Drone_Crash(Predicate):
    time = IntegerField()

class PX4Quadcopter(Device):
    crash_atom = Drone_Crash
    description = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'device.lp')
    def __init__(self, state=None):

        gcs = GCSTelemetry(has_external_input=True)
        sik = SikRadio()
        mavlink = Mavlink()
        px4_cont = PX4ControllerHigh()
        motor = MultiCopterMotor()

        components = [
            gcs, sik, mavlink, px4_cont, motor,
        ]

        super().__init__(
            name="px4_quadcopter_device",
            components=components,
            component_graph=nx.from_edgelist([
                    (gcs, sik),
                    (sik, mavlink),
                    (mavlink, px4_cont),
                    (px4_cont, motor),
                ],
                create_using=nx.DiGraph),
            state=state,
        )

    def update_state(self, state: GlobalState) -> GlobalState:
        pass

