import os
import networkx as nx
from clorm import Predicate, IntegerField
from saci.modeling.state import GlobalState

#from .gcs_telemetry import GCSTelemetry
from saci.modeling.device import Device, GCS, TelemetryHigh, MultiCopterMotor, PWMChannel, ESC, SikRadio, Mavlink, Serial, ICMP, DNNTracking, Wifi, \
                                 ObstacleAvoidanceLogic, ARDiscovery, EmergencyStopLogic, SpeedControlLogic, AttitudeControlLogic, NavigationControlLogic, DSMx, \
                                 ObjectAvoidanceDNN, GNSSReceiver
from saci.modeling.device.sensor import GPSReceiver, Camera, DepthCamera, OpticalFlowSensor, Accelerometer, Gyroscope, Magnetometer, Barometer


from .propriety import ProprietyController

class Drone_Crash(Predicate):
    time = IntegerField()

class ProprietyQuadcopter(Device):
    crash_atom = Drone_Crash
    description = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'device.lp')
    def __init__(self, state=None):

        gcs = GCS(has_external_input=True)
        sik = SikRadio()
        dsmx = DSMx()
        mavlink = Mavlink()
        icmp = ICMP()
        wifi = Wifi(has_external_input=True)

        propriety_telemetry = TelemetryHigh()
        
        gps = GPSReceiver(has_external_input=True)
        gps_serial = Serial()

        gnss = GNSSReceiver(has_external_input=True)
        gnss_serial = Serial()

        accel = Accelerometer(has_external_input=True)
        accel_serial = Serial()

        gyro = Gyroscope(has_external_input=True)
        gyro_serial = Serial(has_external_input=True)

        magnet = Magnetometer(has_external_input=True)
        magnet_serial = Serial(has_external_input=True)

        baro = Barometer(has_external_input=True)
        baro_serial = Serial()

        camera = Camera(has_external_input=True)
        dnn_tracking  = DNNTracking()

        depth_camera = DepthCamera(has_external_input=True)
        dnn_obstacle = ObjectAvoidanceDNN()
        obstacle = ObstacleAvoidanceLogic(has_external_input=True)
        optical_camera = OpticalFlowSensor(has_external_input=True)

        emergency_stop = EmergencyStopLogic(has_external_input=True)
        speed_control = SpeedControlLogic(has_external_input=True)
        attitude_control = AttitudeControlLogic(has_external_input=True)
        navigation_control = NavigationControlLogic(has_external_input=True)

        propriety_cont = ProprietyController(has_external_input=True)
        pwm_channel = PWMChannel(has_external_input=True)
        esc = ESC()
        motor = MultiCopterMotor()

        components = [gcs, sik, dsmx, mavlink, icmp, wifi, propriety_telemetry, gps, gps_serial, accel, accel_serial, gyro, gyro_serial, magnet, magnet_serial,\
                      baro, baro_serial, camera, dnn_tracking, dnn_obstacle, depth_camera, obstacle, optical_camera, emergency_stop, speed_control, attitude_control,\
                        navigation_control, propriety_cont, pwm_channel, esc, motor, gnss_serial, gnss]

        component_graph=nx.from_edgelist([
            (gcs, sik),
            (gcs, wifi),
            (sik, mavlink),
            (sik, dsmx),
            (icmp, propriety_cont),
            (wifi, icmp),
            (wifi, mavlink),

            (dsmx, propriety_telemetry),
            (icmp, propriety_telemetry),
            (wifi, propriety_telemetry),
            (mavlink, propriety_telemetry),
            (propriety_telemetry, propriety_cont),
            
            (gps, gps_serial),
            (gps_serial, propriety_cont),

            (gnss, gnss_serial),
            (gnss_serial, propriety_cont),

            (accel, accel_serial),
            (accel_serial, propriety_cont),

            (gyro, gyro_serial),
            (gyro_serial, propriety_cont),

            (magnet, magnet_serial),
            (magnet_serial, propriety_cont),

            (baro, baro_serial),
            (baro_serial, propriety_cont),

            (optical_camera, propriety_cont),
            
            (camera, dnn_tracking), 

            (depth_camera, obstacle),
            (depth_camera, dnn_obstacle),

            (optical_camera, propriety_cont),

            (dnn_tracking, propriety_cont),
            (obstacle, propriety_cont),
            (dnn_obstacle, propriety_cont),
            (emergency_stop, propriety_cont),
            (speed_control, propriety_cont),
            (attitude_control, propriety_cont),
            (navigation_control, propriety_cont),

            (propriety_cont, pwm_channel),
            (pwm_channel, esc),
            (esc, motor),
        ],
        create_using=nx.DiGraph)

        entry_points = {gcs: True, sik:False, dsmx:False, mavlink:False, icmp:False, wifi:True, propriety_telemetry:False, gps:True, gps_serial:False, \
                        gnss:True, gnss_serial:False, accel:True, accel_serial:True, gyro:True, gyro_serial:True, magnet:True, magnet_serial:True,\
                        baro:True, baro_serial:False, camera:True, dnn_tracking:False, depth_camera:True, dnn_obstacle:False, \
                        obstacle:True, optical_camera:False, emergency_stop:True, speed_control:True, attitude_control:True,\
                        navigation_control:True, propriety_cont:False, pwm_channel:True, esc:False, motor:False}

        nx.set_node_attributes(component_graph, entry_points, 'is_entry')

        super().__init__(
        name="propriety_quadcopter_device",
        components=components,
        component_graph=component_graph,
        state=state,
        )

    def update_state(self, state: GlobalState) -> GlobalState:
        pass

