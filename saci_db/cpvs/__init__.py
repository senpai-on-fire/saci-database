from .cpv01_mavlink_motors import MavlinkCPV
from .cpv02_gps_move import GPSCPV
from .cpv03_deauth_cpv import WiFiDeauthDosCPV
# from .cpv04_icmp_cpv import IcmpFloodCPV


CPVS = [
    MavlinkCPV(),
    GPSCPV(),
    WiFiDeauthDosCPV(),
    # IcmpFloodCPV,
]