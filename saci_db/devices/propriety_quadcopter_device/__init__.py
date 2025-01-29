import os
import networkx as nx
from clorm import Predicate, IntegerField
from saci.modeling.state import GlobalState

from .gcs_telemetry import GCSTelemetry
from saci.modeling.device.sensor import GPSReceiver, Camera, DepthCamera, OpticalFlowSensor
from saci.modeling.device import Device, MultiCopterMotor, ESC, SikRadio, Mavlink, ICMP, DNN, Wifi


from .propriety_controller import ProprietyController

class Drone_Crash(Predicate):
    time = IntegerField()

class ProprietyQuadcopter(Device):
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

        propriety_cont = ProprietyController()
        esc = ESC()
        motor = MultiCopterMotor()

        components = [gcs, sik, mavlink, icmp, wifi, gps, camera, dnn, depth_camera, optical_camera, propriety_cont, esc, motor,]

        component_graph=nx.from_edgelist([
            (sik, mavlink),
            (gcs, mavlink),
            (mavlink, propriety_cont),
            (icmp, propriety_cont),
            (wifi, propriety_cont),
            (gps, propriety_cont),
            (camera, dnn), 
            (dnn, propriety_cont),
            (depth_camera, propriety_cont),
            (optical_camera, propriety_cont),
            (propriety_cont, esc),
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
            propriety_cont: False,
            esc: False,
            motor: False,
        }
        nx.set_node_attributes(component_graph, entry_points, 'is_entry')

        super().__init__(
        name="propriety_quadcopter_device",
        components=components,
        component_graph=component_graph,
        state=state,
        )

    def update_state(self, state: GlobalState) -> GlobalState:
        pass

