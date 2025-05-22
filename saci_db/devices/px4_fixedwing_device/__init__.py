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
    PWMChannel,
    ESC,
    SikRadio,
    Mavlink,
    Serial,
    ICMP,
    Wifi,
    ObstacleAvoidanceLogic,
    Servo,
    FixedWingMotor,
    SpeedControlLogic,
    EmergencyStopLogic,
    SpeedControlLogic,
    AttitudeControlLogic,
    NavigationControlLogic,
    DSMx,
    GNSSReceiver,
    DNNTracking,
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
    AirspeedSensor,
)


from .px4_controller import PX4Controller


class Drone_Crash(Predicate):
    time = IntegerField()


class PX4FixedWing(Device):
    crash_atom = Drone_Crash
    description = os.path.join(os.path.dirname(os.path.realpath(__file__)), "device_fw.lp")

    def __init__(self, state=None):
        gcs = GCS()
        sik = SikRadio()
        dsmx = DSMx()
        mavlink = Mavlink()
        icmp = ICMP()
        wifi = Wifi()

        px4_telemetry = TelemetryHigh()

        airspeed = AirspeedSensor()
        airspeed_serial = Serial()
        
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
        obstacle = ObstacleAvoidanceLogic()
        optical_camera = OpticalFlowSensor()

        emergency_stop = EmergencyStopLogic()
        speed_control = SpeedControlLogic()
        attitude_control = AttitudeControlLogic()
        navigation_control = NavigationControlLogic()

        px4_cont = PX4Controller()

        # throttle ouptut
        pwm_prop = PWMChannel()
        esc_prop = ESC()
        prop_motor = FixedWingMotor()

        # shared rail for control-surface servos
        pwm_ctrl = PWMChannel()
        aileron_servo = Servo()
        elevator_servo = Servo()
        rudder_servo = Servo()

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
            ComponentID("airspeed"): airspeed,
            ComponentID("airspeed_serial"): airspeed_serial,
            ComponentID("baro"): baro,
            ComponentID("baro_serial"): baro_serial,
            ComponentID("camera"): camera,
            ComponentID("dnn_tracking"): dnn_tracking,
            ComponentID("depth_camera"): depth_camera,
            ComponentID("obstacle"): obstacle,
            ComponentID("optical_camera"): optical_camera,
            ComponentID("emergency_stop"): emergency_stop,
            ComponentID("speed_control"): speed_control,
            ComponentID("attitude_control"): attitude_control,
            ComponentID("navigation_control"): navigation_control,
            ComponentID("px4_cont"): px4_cont,
            ComponentID("pwm_prop"): pwm_prop,
            ComponentID("esc_prop"): esc_prop,
            ComponentID("prop_motor"): prop_motor,
            ComponentID("pwm_ctrl"): pwm_ctrl,
            ComponentID("aileron_servo"): aileron_servo,
            ComponentID("elevator_servo"): elevator_servo,
            ComponentID("rudder_servo"): rudder_servo,
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
                (ComponentID("airspeed"), ComponentID("airspeed_serial")),
                (ComponentID("airspeed_serial"), ComponentID("px4_cont")),
                (ComponentID("accel"), ComponentID("accel_serial")),
                (ComponentID("accel_serial"), ComponentID("px4_cont")),
                (ComponentID("gnss"), ComponentID("gnss_serial")),
                (ComponentID("gnss_serial"), ComponentID("px4_cont")),
                (ComponentID("gyro"), ComponentID("gyro_serial")),
                (ComponentID("gyro_serial"), ComponentID("px4_cont")),
                (ComponentID("magnet"), ComponentID("magnet_serial")),
                (ComponentID("magnet_serial"), ComponentID("px4_cont")),
                (ComponentID("airspeed"), ComponentID("airspeed_serial")),
                (ComponentID("airspeed_serial"), ComponentID("px4_cont")),
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
                (ComponentID("px4_cont"), ComponentID("pwm_prop")),
                (ComponentID("pwm_prop"), ComponentID("esc_prop")),
                (ComponentID("esc_prop"), ComponentID("prop_motor")),
                (ComponentID("px4_cont"), ComponentID("pwm_ctrl")),
                (ComponentID("pwm_ctrl"), ComponentID("aileron_servo")),
                (ComponentID("pwm_ctrl"), ComponentID("elevator_servo")),
                (ComponentID("pwm_ctrl"), ComponentID("rudder_servo")),
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
            ComponentID("airspeed"): True,
            ComponentID("airspeed_serial"): False,
            ComponentID("accel"): True,
            ComponentID("accel_serial"): True,
            ComponentID("gyro"): True,
            ComponentID("gyro_serial"): True,
            ComponentID("magnet"): True,
            ComponentID("airspeed"): True,
            ComponentID("airspeed_serial"): True,
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
            ComponentID("px4_cont"): True,
            ComponentID("pwm_prop"): False,
            ComponentID("esc_prop"): False,
            ComponentID("prop_motor"): False,
            ComponentID("pwm_ctrl"): False,
            ComponentID("aileron_servo"): False,
            ComponentID("elevator_servo"): False,
            ComponentID("rudder_servo"): False,
        }

        nx.set_node_attributes(component_graph, entry_points, "is_entry")

        super().__init__(
            name="px4_fixedwing_device",
            components=components,
            component_graph=component_graph,
            state=state,
        )

    def update_state(self, state: GlobalState) -> GlobalState:
        pass
