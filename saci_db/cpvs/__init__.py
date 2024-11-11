from .cpv01_mavlink_motors import MavlinkCPV
from .cpv02_gps_move import GPSCPV
from .cpv03_deauth_cpv import WiFiDeauthDosCPV
# from .cpv04_icmp_cpv import IcmpFloodCPV
# from .cpv05_track_cpv import ObjectTrackCPV
from .cpv06_roll_over import RollOverCPV
from .cpv07_compass_interference import CompassInterferenceCPV
from .cpv08_web_stop import WebStopCPV


CPVS = [
    MavlinkCPV(),
    GPSCPV(),
    WiFiDeauthDosCPV(),
    # IcmpFloodCPV(),
    # ObjectTrackCPV(),
    RollOverCPV(),
    CompassInterferenceCPV(),
    WebStopCPV(),
]