from typing import List, Type

from saci.modeling import CPV
from saci.modeling.communication import ExternalInput

from saci_db.vulns.ardiscovery_flooding_vuln import ARDiscoveryFloodVuln
from saci_db.vulns.lack_wifi_auth_vuln import LackWifiAuthenticationVuln
from saci_db.vulns.lack_wifi_encryption_vuln import LackWifiEncryptionVuln

from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.device import  Wifi, TelemetryHigh, ARDiscovery, PWMChannel, ESC, MultiCopterMotor
from saci.modeling.state import GlobalState

from saci_db.devices.ardupilot_quadcopter_device import ArduPilotController

class ARDiscoveryDoSCPV(CPV):

    NAME = "The ARDiscovery Denial of Service via Wifi"

    def __init__(self):
        super().__init__(
            required_components=[
                Wifi(),
                ARDiscovery(),
                TelemetryHigh(),            
                ArduPilotController(),   
                PWMChannel(),  
                ESC(),
                MultiCopterMotor(), 
            ],
            entry_component=Wifi(),
            exit_component=MultiCopterMotor(),

            vulnerabilities=[ARDiscoveryFloodVuln(), LackWifiAuthenticationVuln(), LackWifiEncryptionVuln()], #TO-DO: Consider adding more vulns

            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any (>0)",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "Moving",
                "OperatingMode": "Manual or Mission",
            },
            
            attack_requirements=[
                "Computer",
                "Wi-Fi card supporting monitor mode",
                "Software for packet crafting (e.g., Scapy, Python libraries, or tools)",
                "Wi-Fi credentials (if ARDiscovery is protected)",
            ],

            attack_vectors=[
                BaseAttackVector(
                    name="ARDiscovery DoS Flooding Attack",
                    signal=PacketAttackSignal(
                        src=ExternalInput(),
                        dst=ARDiscovery(),
                    ),
                    required_access_level="Proximity",
                    configuration={
                        "target_protocol": "ARDiscovery",
                        "flood_type": "Malformed/Excessive ARDiscovery Requests",
                        "interface_name": "wireless",
                        "attack_args": "--max_requests 1000/sec",
                    },
                )
            ],

            attack_impacts=[
                BaseAttackImpact(
                    category='Denial of control',
                    description='Disrupts communication between the UAV and its controller, leading to operational failure or triggering fail-safe mechanisms (e.g., emergency landing).'
                )
            ],

            exploit_steps=[
                "Prepare the hardware: Ensure you have a Wi-Fi card capable of monitor mode and necessary tools (e.g., Scapy, Wireshark).",
                "Scan the Wi-Fi network to identify the UAV's SSID using tools like `airodump-ng`.",
                "Determine the UAV's channel and BSSID via network scanning tools.",
                "Analyze the ARDiscovery protocol by capturing traffic using Wireshark and saving a sample ARDiscovery connection request packet.",
                "Craft malicious packets with tools like Scapy to send excessive/malformed ARDiscovery requests to the UAV.",
                "Flood the UAV with ARDiscovery packets by running a script that sends high-frequency requests.",
                "Monitor the attack's effectiveness by checking if the UAV loses communication with the controller or enters fail-safe mode.",
                "Optional: Post-exploitation—use the disruption to perform further analysis or intercept other communications."
            ],
                
            associated_files=[],
            reference_urls=["https://ieeexplore.ieee.org/document/7795496"]
        )
    
    def in_goal_state(self, state: GlobalState):
        # TODO: Define the specific goal state conditions (e.g., UAV in fail-safe mode)
        pass

