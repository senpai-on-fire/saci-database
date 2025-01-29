import os
import networkx as nx
from clorm import Predicate, IntegerField
from saci.modeling.state import GlobalState

from .gcs_telemetry import GCSTelemetry
from saci.modeling.device import Device, MultiCopterMotor, ESC, SikRadio, Mavlink, GPSReceiver, ICMP, Camera, DNN, DepthCamera, OpticalFlowSensor, Wifi

from .ardupilot_controller import ArduPilotController

class Drone_Crash(Predicate):
    time = IntegerField()

class ArduPilotQuadcopter(Device):
    crash_atom = Drone_Crash
    description = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'device.lp')
    def __init__(self, state=None):

        gcs = GCSTelemetry()
        sik = SikRadio()
        mavlink = Mavlink()
        icmp = ICMP()
        wifi = Wifi()
        
        gps = GPSReceiver()
        camera = Camera()
        dnn  = DNN()
        depth_camera = DepthCamera()
        optical_camera = OpticalFlowSensor()

        ardupilot_cont = ArduPilotController()
        esc = ESC()
        motor = MultiCopterMotor()

        components = [gcs, sik, mavlink, icmp, wifi, gps, camera, dnn, depth_camera, optical_camera, ardupilot_cont, esc, motor,]

        component_graph=nx.from_edgelist([
            (sik, mavlink),
            (gcs, mavlink),
            (mavlink, ardupilot_cont),
            (icmp, ardupilot_cont),
            (wifi, ardupilot_cont),
            (gps, ardupilot_cont),
            (camera, dnn), 
            (dnn, ardupilot_cont),
            (depth_camera, ardupilot_cont),
            (optical_camera, ardupilot_cont),
            (ardupilot_cont, esc),
            (esc, motor),
        ],
        create_using=nx.DiGraph)

        entry_points = {
            gcs: True,
            sik: True,
            mavlink: False,
            icmp: True,
            wifi: True,
            gps: True,
            camera: True,
            dnn: False,
            depth_camera: True,
            optical_camera: True,
            ardupilot_cont: False,
            esc: False,
            motor: False,
        }
        nx.set_node_attributes(component_graph, entry_points, 'is_entry')

        super().__init__(
        name="ardupilot_quadcopter_device",
        components=components,
        component_graph=component_graph,
        state=state,
        )

    def update_state(self, state: GlobalState) -> GlobalState:
        pass

