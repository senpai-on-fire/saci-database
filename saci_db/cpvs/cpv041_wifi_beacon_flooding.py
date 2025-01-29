from typing import List, Type

from saci.modeling import CPV
from saci.modeling.communication import ExternalInput

from saci_db.vulns.lack_wifi_auth_vuln import LackWifiAuthenticationVuln
from saci_db.vulns.lack_wifi_encryption_vuln import LackWifiEncryptionVuln
from saci_db.vulns.lack_beacon_filtering_vuln import LackBeaconFilteringVuln

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

            vulnerabilities=[LackBeaconFilteringVuln(), LackWifiAuthenticationVuln(), LackWifiEncryptionVuln()],

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
                "Access to the UAV's Wi-Fi network (proximity)",
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
                        "target": "UAV Wi-Fi interface",
                    },
                )
            ],

            attack_impacts=[
                BaseAttackImpact(
                    category="Denial of Service",
                    description="Prevents the UAV from associating with its controller by overwhelming it with beacon frames."
                )
            ],

            exploit_steps=[
                "Identify the target Wi-Fi network used by the UAV (e.g., using `airodump-ng`).",
                "Craft malicious beacon frames with tools like Scapy or aireplay-ng.",
                "Send a high volume of beacon frames to the UAV's Wi-Fi channel.",
                "Monitor the UAV's response (e.g., loss of communication or fail-safe activation)."
            ],

            associated_files=[],
            reference_urls=["https://medium.com/@angelinatsuboi/drone-swarmer-uncovering-vulnerabilities-in-open-drone-id-cdd8d1a23c2c",
                            "https://dl.acm.org/doi/pdf/10.1145/3395351.3399442?casa_token=x2LV35bFGowAAAAA:X9TRtxKCpHQtY1ooiZgr4xszKrAUNb0_7m4JWLMjW-Ttr4Rxc-wtyRysnF4qD03ivfbX3W5OsVLSpQ"]
        )

    def in_goal_state(self, state: GlobalState):
        # Define the goal state conditions, such as the UAV failing to associate with its controller
        return state.has_property("CommunicationLoss", True)
