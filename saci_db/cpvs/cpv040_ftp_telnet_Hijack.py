from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import Wifi, TelemetryHigh, Telnet, FTP, ESC, PWMChannel, MultiCopterMotor

from saci_db.vulns.wifi_deauthentication_vuln import WiFiDeauthVuln
from saci_db.vulns.lack_wifi_auth_vuln import LackWifiAuthenticationVuln
from saci_db.vulns.lack_wifi_encryption_vuln import LackWifiEncryptionVuln
from saci_db.vulns.open_telnet_vuln import OpenTelnetVuln
from saci_db.vulns.open_ftp_vuln import OpenFTPVuln

from saci.modeling.communication import ExternalInput
from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.state import GlobalState

from saci_db.devices.ardupilot_quadcopter_device import ArduPilotController

class FTPTelnetHijackCPV(CPV):

    NAME = "Parrot Bebop 2 Drone Hijacking via FTP and Telnet"

    def __init__(self):
        super().__init__(
            required_components=[
                Wifi(),
                Telnet(),
                FTP(),
                TelemetryHigh(),   
                ArduPilotController(),
                PWMChannel(),
                ESC(),
                MultiCopterMotor(),
            ],

            entry_component=Wifi(),
            exit_component=MultiCopterMotor(),

            vulnerabilities=[WiFiDeauthVuln(), LackWifiAuthenticationVuln(), LackWifiEncryptionVuln(), OpenTelnetVuln(), OpenFTPVuln()],

            initial_conditions={
                "WiFi": "Open Access (No WPA/WPA2)",
                "Telnet": "Enabled (No Authentication)",
                "FTP": "Accessible (No Authentication)",
                "Controller": "Active",
                "Drone Status": "Flying",
                "Environment": "Urban Area",
                "OperatingMode": "Manual or Mission",
            },

            attack_requirements=[
                "Laptop or device capable of network scanning and packet injection",
                "WiFi card with monitor mode",
                "Aircrack-ng software",
                "Proximity to the drone's WiFi range",
            ],

            attack_vectors=[
                BaseAttackVector(
                    name="Deauthentication Attack to Hijack Control",
                    signal=PacketAttackSignal(src=ExternalInput(), dst=Wifi()),
                    required_access_level="Proximity",
                    configuration={
                        "BSSID": "Drone's WiFi Access Point",
                        "interface_name": "Wireless Interface",
                        "other_args": "-0 0 -a",
                    },
                ),
                BaseAttackVector(
                    name="Telnet Access for Root Control",
                    signal=PacketAttackSignal(src=ExternalInput(), dst=Telnet()),
                    required_access_level="Proximity",
                    configuration={},
                ),
                BaseAttackVector(
                    name="FTP Exploitation to Extract Data",
                    signal=PacketAttackSignal(src=ExternalInput(), dst=FTP()),
                    required_access_level="Proximity",
                    configuration={},
                ),
            ],

            attack_impacts=[
                BaseAttackImpact(
                    category="Denial of Control",
                    description="The user cannot stop or control the drone after deauthentication."
                ),
                BaseAttackImpact(
                    category="Manipulation of Control",
                    description="The attacker gains root access via Telnet, enabling system-level manipulations."
                ),
            ],

            exploit_steps=[
                "Set the Wi-Fi card into monitor mode and locate the drone's BSSID and channel.",
                "Send continuous deauthentication packets to disconnect the legitimate controller.",
                "Establish a Telnet session to gain root access to the drone.",
                "Access the FTP service to extract data or modify critical files.",
                "Optionally modify the drone's configuration to disrupt its operations or cause a crash."
            ],

            associated_files=[],
            reference_urls=["https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8326960"]
        )

        self.goal_state = []

    def in_goal_state(self, state: GlobalState):
        # TODO: Implement goal state logic if required.
        pass
