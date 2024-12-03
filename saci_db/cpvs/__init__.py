from .cpv01_mavlink_motors import MavlinkCPV
from .cpv02_gps_position_move import GPSCPV
from .cpv03_deauth_dos import WiFiDeauthDosCPV
from .cpv04_icmp_cpv import IcmpFloodCPV
# from .cpv05_adv_ml_untrack import ObjectTrackCPV
from .cpv06_serial_motor_rollover import RollOverCPV
from .cpv07_pmagnet_compass_dos import CompassInterferenceCPV
from .cpv08_wifi_webserver_stop import WebStopCPV


CPVS = [
    MavlinkCPV(),
    GPSCPV(),
    WiFiDeauthDosCPV(),
    IcmpFloodCPV(),
    # ObjectTrackCPV(),
    RollOverCPV(),
    CompassInterferenceCPV(),
    WebStopCPV(),
]