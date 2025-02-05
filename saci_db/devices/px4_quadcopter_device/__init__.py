import os
import networkx as nx
from clorm import Predicate, IntegerField
from saci.modeling.state import GlobalState

#from .gcs_telemetry import GCSTelemetry
from saci.modeling.device import Device, GCS, TelemetryHigh, MultiCopterMotor, PWMChannel, ESC, SikRadio, Mavlink, Serial, ICMP, DNNTracking, Wifi, \
                                 ObstacleAvoidanceLogic, ARDiscovery, EmergencyStopLogic, SpeedControlLogic, AttitudeControlLogic, NavigationControlLogic, DSMx, \
                                 ObjectAvoidanceDNN, GNSSReceiver
from saci.modeling.device.sensor import GPSReceiver, Camera, DepthCamera, OpticalFlowSensor, Accelerometer, Gyroscope, Magnetometer, Barometer


from .px4_controller import PX4Controller

class Drone_Crash(Predicate):
    time = IntegerField()

class PX4Quadcopter(Device):
    crash_atom = Drone_Crash
    description = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'device.lp')
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
        dnn_tracking  = DNNTracking()

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

        components = [gcs, sik, dsmx, mavlink, icmp, wifi, px4_telemetry, gps, gps_serial, accel, accel_serial, gyro, gyro_serial, magnet, magnet_serial,\
                      baro, baro_serial, camera, dnn_tracking, dnn_obstacle, depth_camera, obstacle, optical_camera, emergency_stop, speed_control, attitude_control,\
                        navigation_control, px4_cont, pwm_channel, esc, motor, gnss, gnss_serial]

        component_graph=nx.from_edgelist([
            (gcs, sik),
            (gcs, wifi),
            (sik, mavlink),
            (sik, dsmx),
            (icmp, px4_cont),
            (wifi, icmp),
            (wifi, mavlink),

            (dsmx, px4_telemetry),
            (icmp, px4_telemetry),
            (wifi, px4_telemetry),
            (mavlink, px4_telemetry),
            (px4_telemetry, px4_cont),
            
            (gps, gps_serial),
            (gps_serial, px4_cont),

            (accel, accel_serial),
            (accel_serial, px4_cont),

            (gnss, gnss_serial),
            (gnss_serial, px4_cont),

            (gyro, gyro_serial),
            (gyro_serial, px4_cont),

            (magnet, magnet_serial),
            (magnet_serial, px4_cont),

            (baro, baro_serial),
            (baro_serial, px4_cont),

            (optical_camera, px4_cont),
            
            (camera, dnn_tracking), 

            (depth_camera, obstacle),
            (depth_camera, dnn_obstacle),

            (optical_camera, px4_cont),

            (dnn_tracking, px4_cont),
            (obstacle, px4_cont),
            (dnn_obstacle, px4_cont),
            (emergency_stop, px4_cont),
            (speed_control, px4_cont),
            (attitude_control, px4_cont),
            (navigation_control, px4_cont),

            (px4_cont, pwm_channel),
            (pwm_channel, esc),
            (esc, motor),
        ],
        create_using=nx.DiGraph)

        entry_points = {gcs: True, sik:False, dsmx:False, mavlink:False, icmp:False, wifi:True, px4_telemetry:False, gps:True, gps_serial:False, \
                        accel:True, accel_serial:True, gyro:True, gyro_serial:True, magnet:True, magnet_serial:True,\
                        baro:True, baro_serial:False, camera:True, dnn_tracking:False, depth_camera:True, dnn_obstacle:False, \
                        obstacle:True, optical_camera:False, emergency_stop:True, speed_control:True, attitude_control:True,\
                        navigation_control:True, px4_cont:False, pwm_channel:True, esc:False, motor:False}

        nx.set_node_attributes(component_graph, entry_points, 'is_entry')

        super().__init__(
        name="px4_quadcopter_device",
        components=components,
        component_graph=component_graph,
        state=state,
        )

    def update_state(self, state: GlobalState) -> GlobalState:
        pass
