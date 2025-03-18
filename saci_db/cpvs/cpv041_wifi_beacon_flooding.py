from typing import List, Type

from saci.modeling import CPV
from saci.modeling.communication import ExternalInput

from saci_db.vulns.lack_wifi_auth_vuln import LackWifiAuthenticationVuln
from saci_db.vulns.lack_wifi_encryption_vuln import LackWifiEncryptionVuln
from saci_db.vulns.lack_beacon_filtering_vuln import LackBeaconFilteringVuln
from saci_db.vulns.wifi_knowncreds_vuln import WifiKnownCredsVuln
from saci_db.vulns.payload_firmware_vuln import FirmwarePayloadVuln

from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci_db.devices.px4_quadcopter_device import PX4Controller
from saci.modeling.device import Wifi, TelemetryHigh, ESC, PWMChannel, MultiCopterMotor
from saci.modeling.state import GlobalState


class BeaconFrameFloodingCPV(CPV):

    NAME = "The Beacon Frame Flooding via Wifi"

    def __init__(self):
        super().__init__(
            required_components=[
                Wifi(), 
                TelemetryHigh(),            
                PX4Controller(),   
                PWMChannel(),  
                ESC(),
                MultiCopterMotor(),                     
            ],
            entry_component=Wifi(),        
            exit_component=MultiCopterMotor(),

            vulnerabilities=[LackBeaconFilteringVuln(), LackWifiAuthenticationVuln(), LackWifiEncryptionVuln(), WifiKnownCredsVuln(), FirmwarePayloadVuln()],

            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any (>0)",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "Active",
                "Operating mode": "Manual or Semi-Autonomous",
            },

            attack_requirements=[
                "Computer with Wi-Fi card supporting monitor mode",
                "Packet crafting tools (e.g., Scapy, aireplay-ng)",
                "Access to the CPS's Wi-Fi network (proximity)",
            ],

            attack_vectors=[
                BaseAttackVector(
                    name="Beacon Frame Flooding",
                    signal=PacketAttackSignal(
                        src=ExternalInput(),
                        dst=Wifi(),
                    ),
                    required_access_level="Proximity",
                    configuration={
                        "attack_method": "Flood with beacon frames",
                        "frequency": "High",
                        "target": "CPS Wi-Fi interface",
                        "frame_type": "beacon",
                        "delivery_method": {
                            "broadcast": True,
                            "unicast": True
                        },
                        "injection_timing": "after_legitimate_beacon",
                        "elements": [
                            "WMM",
                            "power_constraint",
                            "t",
                            "TIM", 
                            "CSA"
                        ],
                        "beacon_interval": "102.4ms"
                    },
                )
            ],

            attack_impacts=[
                BaseAttackImpact(
                    category="Denial of Service",
                    description="Prevents the CPS from associating with its controller by overwhelming it with beacon frames."
                )
            ],

            exploit_steps = [
                "TA1 Exploit Steps",
                    "Install the ModWifi framework and aircrack-ng suite.",
                    "Set the Wi-Fi interface to monitoring mode.",
                    "Use airodump-ng to identify the target CPS's Wi-Fi network parameters, including:: SSID, Channel, BSSID",
                    "Capture and analyze the following settings in legitimate beacon frames using Wireshark or airodump-ng:",
                    "    - WMM settings",
                    "    - TIM (Traffic Indication Map) elements",
                    "    - Transmission power constraints",

                "TA2 Exploit Steps",
                    "Craft malicious beacon frames with manipulated parameters, including:",
                    "    - Malicious power constraint values",
                    "    - Country information elements",
                    "    - Power constraint IEs along with Cisco Dynamic Transmit Power Control IE",
                    "Construct malicious beacons with extreme EDCA parameters based on extracted WMM update counts.",
                    "Modify TIM elements to indicate buffered frames waiting for all clients.",
                    "Create malicious beacons with Channel Switch Announcement (CSA) elements.",
                    "Ensure all attack payloads can be injected through the ModWifi framework.",

                "TA3 Exploit Steps",
                    "Inject forged beacon frames after legitimate ones using the ModWifi framework.",
                    "Monitor CPS responses using airodump-ng or Wireshark.",
                    "Measure network performance changes using iperf3.",
                    "Verify the attack effects on:",
                    "    - Transmission power",
                    "    - Network throughput",
                    "    - Battery consumption",
                    "    - Channel switching"
                ],

            associated_files=[],
            reference_urls=["https://medium.com/@angelinatsuboi/drone-swarmer-uncovering-vulnerabilities-in-open-drone-id-cdd8d1a23c2c",
                            "https://dl.acm.org/doi/pdf/10.1145/3395351.3399442?casa_token=x2LV35bFGowAAAAA:X9TRtxKCpHQtY1ooiZgr4xszKrAUNb0_7m4JWLMjW-Ttr4Rxc-wtyRysnF4qD03ivfbX3W5OsVLSpQ"]
        )

    def in_goal_state(self, state: GlobalState):
        # Define the goal state conditions, such as the CPS failing to associate with its controller
        return state.has_property("CommunicationLoss", True)
