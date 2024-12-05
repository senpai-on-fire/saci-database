from .cpv01_sik_mavlink_motors import MavlinkCPV
from .cpv02_gps_position_move import GPSCPV
from .cpv03_deauth_dos import WiFiDeauthDosCPV
from .cpv04_icmp_cpv import ICMPFloodingCPV
# from .cpv05_adv_ml_untrack import ObjectTrackCPV
from .cpv06_serial_motor_rollover import RollOverCPV
from .cpv07_pmagnet_compass_dos import PermanentCompassSpoofingCPV
from .cpv08_wifi_webserver_crash import WebCrashCPV
from .cpv09_gps_position_static import GPSPositionStaticCPV
from .cpv11_serial_motor_throttle import ThrottleCPV
from .cpv12_wifi_http_move import WebMoveCPV
from .cpv13_gps_position_loop import GPSPositionLoopCPV
from .cpv14_serial_arduino_control import SerialArduinoControlCPV
from .cpv15_wifi_http_stop import WebStopCPV
from .cpv16_serial_motor_redirect import RedirectCPV
from .cpv17_tmagnet_compass_disorient import TemporaryCompassSpoofingCPV

from .cpv32_deauth_quad_dos import WiFiDeauthQuadDosCPV
from .cpv33_wifi_mavlink_disarm import MavlinkDisarmCPV

CPVS = [
    MavlinkCPV(),
    GPSCPV(),
    GPSPositionStaticCPV(),
    WiFiDeauthDosCPV(),
    ICMPFloodingCPV(),
    # ObjectTrackCPV(),
    RollOverCPV(),
    PermanentCompassSpoofingCPV(),
    WebCrashCPV(),
    ThrottleCPV(),
    WebMoveCPV(),
    GPSPositionLoopCPV(),
    SerialArduinoControlCPV(),
    WebStopCPV(),
    RedirectCPV(),
    TemporaryCompassSpoofingCPV(),
    WiFiDeauthQuadDosCPV(),
    MavlinkDisarmCPV(),
]