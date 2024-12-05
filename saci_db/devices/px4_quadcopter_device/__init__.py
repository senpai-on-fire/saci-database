import os
import networkx as nx
from clorm import Predicate, IntegerField
from saci.modeling.state import GlobalState

from .gcs_telemetry import GCSTelemetry
from saci.modeling.device import Device, MultiCopterMotor, ESC, SikRadio, Mavlink, GPSReceiver, ICMP, Camera, DNN, DepthCamera, OpticalFlowSensor

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
        icmp = ICMP()
        
        gps = GPSReceiver()
        camera = Camera()
        dnn  = DNN()
        depth_camera = DepthCamera()
        optical_camera = OpticalFlowSensor()

        px4_cont = PX4Controller()
        esc = ESC()
        motor = MultiCopterMotor()

        components = [gcs, sik, mavlink, icmp, gps, camera, dnn, depth_camera, optical_camera, px4_cont, esc, motor,]

        component_graph=nx.from_edgelist([
            (gcs, sik),
            (gcs, mavlink),
            (gcs, icmp),
            (sik, px4_cont),
            (mavlink, px4_cont),
            (icmp, px4_cont),
            (gps, px4_cont),
            (camera, dnn), 
            (dnn, px4_cont),
            (depth_camera, px4_cont),
            (optical_camera, px4_cont),
            (px4_cont, esc),
            (esc, motor),
        ],
        create_using=nx.DiGraph)

        components = [gcs, sik, mavlink, icmp, gps, camera, dnn, depth_camera, optical_camera, px4_cont, esc, motor,]

        entry_points = {
            gcs: True, 
            sik: False,
            mavlink: False,
            icmp: False,
            gps: True,
            camera: True,
            dnn: False,
            depth_camera: True,
            optical_camera: True,
            px4_cont: False,
            esc: False,
            motor: False,
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

