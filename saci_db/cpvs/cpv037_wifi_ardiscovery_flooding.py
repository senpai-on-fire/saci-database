
from saci.modeling import CPV
from saci.modeling.communication import ExternalInput

from saci_db.vulns.ardiscovery_flooding_vuln import ARDiscoveryFloodVuln
from saci_db.vulns.lack_wifi_auth_vuln import LackWifiAuthenticationVuln

from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.device import Controller

from saci.modeling.device import (
    Wifi,
    ARDiscovery,
    Motor
)
from saci.modeling.state import GlobalState



class ARDiscoveryDoSCPV(CPV):
    NAME = "The ARDiscovery Denial of Service via Wifi"

    def __init__(self):
        super().__init__(
            
            required_components=[
                Wifi(), # This is the entry component (Required)
                ARDiscovery(), # ARDiscovery is a required vulnerable component (Required)
                Controller(), # This is the controller hosting the firmware (Required)
                # PWMChannel(), # Removed since the PWMChannel is just a passthrough for the CPV (Not Required)
                # ESC(), # Removed since the ESC is just a passthrough for the CPV (Not Required)
                Motor(), # This is the exit component + Changed to Motor() for generalization (Required)
            ],
            
            entry_component=Wifi(),
            exit_component=Motor(),
            
            vulnerabilities=[
                ARDiscoveryFloodVuln(),
                LackWifiAuthenticationVuln(),
            ],  # TO-DO: Consider adding more vulns
            
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
                    category="Denial of control",
                    description="Disrupts communication between the CPS and its controller, leading to operational failure or triggering fail-safe mechanisms (e.g., emergency landing).",
                )
            ],
            
            exploit_steps=[
                "TA1 Exploit Steps",
                    "Reverse-engineer the CPS firmware to determine if the Wi-Fi implements security mechanisms such as Management Frame Protection (MFP).",
                    "Identify if the firmware has failsafe mechanisms to recover from ARDiscovery flooding attack.",
                    "Analyze the CPS control logic to assess how high frequency ARDiscovery requests impact the CPS movement and operation.",
                    "Create models for the following components: Ground Control Station, Wifi with an ARDisovery protocol, CPS control logic, ESC logic and output, CPS actuators (e.g., motors) controlled by the ESC.",
                    "Report to TA2 any required physical parameters to simulate the CPS dynamics",
                "TA2 Exploit Steps",
                    "Implement a simulation of an ARDiscovery flooding attack over Wi-Fi in the CPS model.",
                    "Run the simulation to analyze how loss of communication translates to control failure in the CPS device.",
                    "Check with TA1 to determine the desired impact on control.",
                    "Report the findings to TA3 to conduct the experiments on the physical CPS device",
                "TA3 Exploit Steps",
                    "Use imaging tools and other techniques to catalog all Wi-Fi-related hardware components on the CPS.",
                    "Identify if the ARDiscovery protocol is used in the networking system.",
                    "Identify the specific Wi-Fi module and extract the Wi-Fi SSID and password.",
                    "Prepare the hardware: Ensure you have a Wi-Fi card capable of monitor mode and necessary tools (e.g., Scapy, Wireshark).",
                    "Scan the Wi-Fi network to identify the CPS's SSID using tools like `airodump-ng`.",
                    "Determine the CPS's channel and BSSID via network scanning tools.",
                    "Analyze the ARDiscovery protocol by capturing traffic using Wireshark and saving a sample ARDiscovery connection request packet.",
                    "Craft malicious packets with tools like Scapy to send excessive/malformed ARDiscovery requests to the CPS.",
                    "Flood the CPS with ARDiscovery packets by running a script that sends high-frequency requests.",
                    "Monitor the attack's effectiveness by checking if the CPS loses communication with the controller or enters fail-safe mode.",
                    "Optional: Post-exploitation—use the disruption to perform further analysis or intercept other communications.",
            ],
            associated_files=[],
            reference_urls=["https://ieeexplore.ieee.org/document/7795496"],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO: Define the specific goal state conditions (e.g., CPS in fail-safe mode)
        pass
