import os
import networkx as nx
from clorm import Predicate, IntegerField
from saci.modeling.state import GlobalState

# from .gcs_telemetry import GCSTelemetry
from saci.modeling.device import (
    ComponentID,
    Device,
    GCS,
    TelemetryHigh,
    MultiCopterMotor,
    PWMChannel,
    ESC,
    SikRadio,
    Mavlink,
    Serial,
    ICMP,
    DNNTracking,
    Wifi,
    ObstacleAvoidanceLogic,
    ARDiscovery,
    EmergencyStopLogic,
    SpeedControlLogic,
    AttitudeControlLogic,
    NavigationControlLogic,
    DSMx,
    ObjectAvoidanceDNN,
    GNSSReceiver,
)
from saci.modeling.device.sensor import (
    GPSReceiver,
    Camera,
    DepthCamera,
    OpticalFlowSensor,
    Accelerometer,
    Gyroscope,
    Magnetometer,
    Barometer,
)


from .px4_controller import PX4Controller


class Drone_Crash(Predicate):
    time = IntegerField()


class PX4Quadcopter(Device):
    crash_atom = Drone_Crash
    description = os.path.join(os.path.dirname(os.path.realpath(__file__)), "device.lp")

    def __init__(self, state=None):
        gcs = GCS()
        sik = SikRadio()
        dsmx = DSMx()
        mavlink = Mavlink()
        icmp = ICMP()
        wifi = Wifi()

        px4_telemetry = TelemetryHigh()

        gps = GPSReceiver()
        gps_serial = Serial()

        gnss = GNSSReceiver()
        gnss_serial = Serial()

        accel = Accelerometer()
        accel_serial = Serial()

        gyro = Gyroscope()
        gyro_serial = Serial()

        magnet = Magnetometer()
        magnet_serial = Serial()

        baro = Barometer()
        baro_serial = Serial()

        camera = Camera()
        dnn_tracking = DNNTracking()

        depth_camera = DepthCamera()
        dnn_obstacle = ObjectAvoidanceDNN()
        obstacle = ObstacleAvoidanceLogic()
        optical_camera = OpticalFlowSensor()

        emergency_stop = EmergencyStopLogic()
        speed_control = SpeedControlLogic()
        attitude_control = AttitudeControlLogic()
        navigation_control = NavigationControlLogic()

        px4_cont = PX4Controller()
        pwm_channel = PWMChannel()
        esc = ESC()
        motor = MultiCopterMotor()

        components = {
            ComponentID("gcs"): gcs,
            ComponentID("sik"): sik,
            ComponentID("dsmx"): dsmx,
            ComponentID("mavlink"): mavlink,
            ComponentID("icmp"): icmp,
            ComponentID("wifi"): wifi,
            ComponentID("px4_telemetry"): px4_telemetry,
            ComponentID("gps"): gps,
            ComponentID("gps_serial"): gps_serial,
            ComponentID("accel"): accel,
            ComponentID("accel_serial"): accel_serial,
            ComponentID("gyro"): gyro,
            ComponentID("gyro_serial"): gyro_serial,
            ComponentID("magnet"): magnet,
            ComponentID("magnet_serial"): magnet_serial,
            ComponentID("baro"): baro,
            ComponentID("baro_serial"): baro_serial,
            ComponentID("camera"): camera,
            ComponentID("dnn_tracking"): dnn_tracking,
            ComponentID("dnn_obstacle"): dnn_obstacle,
            ComponentID("depth_camera"): depth_camera,
            ComponentID("obstacle"): obstacle,
            ComponentID("optical_camera"): optical_camera,
            ComponentID("emergency_stop"): emergency_stop,
            ComponentID("speed_control"): speed_control,
            ComponentID("attitude_control"): attitude_control,
            ComponentID("navigation_control"): navigation_control,
            ComponentID("px4_cont"): px4_cont,
            ComponentID("pwm_channel"): pwm_channel,
            ComponentID("esc"): esc,
            ComponentID("motor"): motor,
            ComponentID("gnss"): gnss,
            ComponentID("gnss_serial"): gnss_serial,
        }

        component_graph = nx.from_edgelist(
            [
                (ComponentID("gcs"), ComponentID("sik")),
                (ComponentID("gcs"), ComponentID("wifi")),
                (ComponentID("sik"), ComponentID("mavlink")),
                (ComponentID("sik"), ComponentID("dsmx")),
                (ComponentID("icmp"), ComponentID("px4_cont")),
                (ComponentID("wifi"), ComponentID("icmp")),
                (ComponentID("wifi"), ComponentID("mavlink")),
                (ComponentID("dsmx"), ComponentID("px4_telemetry")),
                (ComponentID("icmp"), ComponentID("px4_telemetry")),
                (ComponentID("wifi"), ComponentID("px4_telemetry")),
                (ComponentID("mavlink"), ComponentID("px4_telemetry")),
                (ComponentID("px4_telemetry"), ComponentID("px4_cont")),
                (ComponentID("gps"), ComponentID("gps_serial")),
                (ComponentID("gps_serial"), ComponentID("px4_cont")),
                (ComponentID("accel"), ComponentID("accel_serial")),
                (ComponentID("accel_serial"), ComponentID("px4_cont")),
                (ComponentID("gnss"), ComponentID("gnss_serial")),
                (ComponentID("gnss_serial"), ComponentID("px4_cont")),
                (ComponentID("gyro"), ComponentID("gyro_serial")),
                (ComponentID("gyro_serial"), ComponentID("px4_cont")),
                (ComponentID("magnet"), ComponentID("magnet_serial")),
                (ComponentID("magnet_serial"), ComponentID("px4_cont")),
                (ComponentID("baro"), ComponentID("baro_serial")),
                (ComponentID("baro_serial"), ComponentID("px4_cont")),
                (ComponentID("optical_camera"), ComponentID("px4_cont")),
                (ComponentID("camera"), ComponentID("dnn_tracking")),
                (ComponentID("depth_camera"), ComponentID("obstacle")),
                (ComponentID("depth_camera"), ComponentID("dnn_obstacle")),
                (ComponentID("optical_camera"), ComponentID("px4_cont")),
                (ComponentID("dnn_tracking"), ComponentID("px4_cont")),
                (ComponentID("obstacle"), ComponentID("px4_cont")),
                (ComponentID("dnn_obstacle"), ComponentID("px4_cont")),
                (ComponentID("emergency_stop"), ComponentID("px4_cont")),
                (ComponentID("speed_control"), ComponentID("px4_cont")),
                (ComponentID("attitude_control"), ComponentID("px4_cont")),
                (ComponentID("navigation_control"), ComponentID("px4_cont")),
                (ComponentID("px4_cont"), ComponentID("pwm_channel")),
                (ComponentID("pwm_channel"), ComponentID("esc")),
                (ComponentID("esc"), ComponentID("motor")),
            ],
            create_using=nx.DiGraph,
        )

        entry_points = {
            ComponentID("gcs"): True,
            ComponentID("sik"): False,
            ComponentID("dsmx"): False,
            ComponentID("mavlink"): False,
            ComponentID("icmp"): False,
            ComponentID("wifi"): True,
            ComponentID("px4_telemetry"): False,
            ComponentID("gps"): True,
            ComponentID("gps_serial"): False,
            ComponentID("accel"): True,
            ComponentID("accel_serial"): True,
            ComponentID("gyro"): True,
            ComponentID("gyro_serial"): True,
            ComponentID("magnet"): True,
            ComponentID("magnet_serial"): True,
            ComponentID("baro"): True,
            ComponentID("baro_serial"): False,
            ComponentID("camera"): True,
            ComponentID("dnn_tracking"): False,
            ComponentID("depth_camera"): True,
            ComponentID("dnn_obstacle"): False,
            ComponentID("obstacle"): True,
            ComponentID("optical_camera"): False,
            ComponentID("emergency_stop"): True,
            ComponentID("speed_control"): True,
            ComponentID("attitude_control"): True,
            ComponentID("navigation_control"): True,
            ComponentID("px4_cont"): False,
            ComponentID("pwm_channel"): True,
            ComponentID("esc"): False,
            ComponentID("motor"): False,
        }

        nx.set_node_attributes(component_graph, entry_points, "is_entry")

        super().__init__(
            name="px4_quadcopter_device",
            components=components,
            component_graph=component_graph,
            state=state,
        )

    def update_state(self, state: GlobalState) -> GlobalState:
        pass
