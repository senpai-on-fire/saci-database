import os.path
from typing import Iterator
from clorm import Predicate

from saci.modeling.vulnerability import (
    VulnerabilityEffect,
    MakeEntryEffect,
    BaseVulnerability,
)
from saci.modeling.device import (
    ComponentID,
    Device,
    Wifi,
    TelemetryHigh,
    ICMP,
    ARDiscovery,
)
from saci.modeling.communication import UnauthenticatedCommunication, ExternalInput
from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack import BaseCompEffect
from saci.modeling.attack.base_attack_vector import BaseAttackVector


# Predicate to define formal reasoning logic for vulnerabilities caused by lack of authentication in WiFi communication
class LackWifiAuthenticationPred(Predicate):
    pass


class LackWifiAuthenticationVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            # The Wifi component is vulnerable due to a lack of proper authentication mechanisms
            component=Wifi(),
            # Input: Unauthenticated communication exploited by an external attacker
            _input=UnauthenticatedCommunication(src=ExternalInput()),
            # Output: Unauthenticated communication representing compromised data or unauthorized access
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about the lack of authentication in WiFi communication
            attack_ASP=LackWifiAuthenticationPred,
            # Logic rules for evaluating this vulnerability in formal reasoning
            rulefile=os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                "lack_wifi_authentication.lp",
            ),
            # List of Associated CWEs:
            associated_cwe=[
                "CWE-287: Improper Authentication",
                "CWE-294: Authentication Bypass by Capture-replay",
                "CWE-306: Missing Authentication for Critical Function",
                "CWE-345: Insufficient Verification of Data Authenticity",
                "CWE-20: Improper Input Validation",
                "CWE-1188: Insecure Default Initialization of Resource",
                "CWE-295: Improper Certificate Validation",
            ],
            attack_vectors=[
                {
                    # List of related attack vectors and their exploitation information
                    "attack_vector": [
                        BaseAttackVector(
                            name="MavLink Packets Injection",
                            signal=PacketAttackSignal(
                                src=ExternalInput(), dst=TelemetryHigh()
                            ),
                            required_access_level="Proximity",
                        )
                    ],
                    # List of associated CPVs
                    "related_cpv": ["LackWifiAuthenticationVuln"],
                    # List of associated component-level attack effects
                    "comp_attack_effect": BaseCompEffect(
                        category="Availability",
                        description="Denial of Service. The CPS crashes into the ground.",
                    ),
                    # Steps of exploiting this attack vector
                    "exploit_steps": {
                        "TA1 Exploit Steps": [
                            "Collaborate with TA2 to obtain the extracted firmware.",
                            "Reverse-engineer the CPS firmware to determine if it implements security mechanisms such as MAVLink encryption or authentication.",
                            "Identify if the firmware has failsafe mechanisms to prevent unauthorized disarm commands.",
                            "Analyze the CPS control logic to assess how receiving an unauthorized disarm command affects the drone’s operation.",
                        ],
                        "TA2 Exploit Steps": [
                            "Implement a simulation of the ARP poisoning attack to establish a Man-In-The-Middle (MITM) position between the ground control station (GCS) and the drone.",
                            "Simulate the impact of sending a malicious MAVLink disarm command to the drone.",
                            "Collaborate with TA1 to determine the severity of the attack and possible escalation paths.",
                        ],
                        "TA3 Exploit Steps": [
                            "Use imaging tools and other techniques to catalog all Wi-Fi-related hardware components on the drone.",
                            "Identify physical interfaces that allow firmware extraction from the drone's flight controller.",
                            "Identify the specific MAVLink version used and whether encryption/authentication is enabled.",
                            "Join the drone’s open Wi-Fi network.",
                            "Set up ARP poisoning to become a MITM between the ground control station (GCS) and the drone.",
                            "Capture MAVLink messages exchanged between the GCS and the drone.",
                            "Modify and inject a malicious MAVLink disarm command into the communication channel.",
                            "Observe that the drone disarms and verify that the ground control station loses control over it.",
                            "Log network traffic and MAVLink messages before, during, and after the attack.",
                            "Analyze the CPS’s physical response to the disarm command using telemetry and external tracking.",
                        ],
                    },
                    # List of related references
                    "reference_urls": [
                        "https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8425627&tag=1",
                        "Add a video link",
                    ],
                },
                {
                    # List of related attack vectors and their exploitation information
                    "attack_vector": [
                        BaseAttackVector(
                            name="Deauthentication WiFi Packets Injection",
                            signal=PacketAttackSignal(src=ExternalInput(), dst=Wifi()),
                            required_access_level="Proximity",
                        )
                    ],
                    # List of associated CPVs
                    "related_cpv": ["WiFiDeauthDosCPV"],
                    # List of associated component-level attack effects
                    "comp_attack_effect": BaseCompEffect(
                        category="Availability",
                        description="Denial of Control. The user cannot stop the CPS.",
                    ),
                    # Steps of exploiting this attack vector
                    "exploit_steps": [
                        "Set the Wi-Fi card into monitor mode and find the BSSID and channel number for the CPS's Wi-Fi network.",
                        "Send a deauthentication packet to the Wi-Fi interface.",
                    ],
                    # List of related references
                    "reference_urls": [
                        "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/blob/main/CPV001"
                    ],
                },
                {
                    # List of related attack vectors and their exploitation information
                    "attack_vector": [
                        BaseAttackVector(
                            name="ICMP Packets Injection",
                            signal=PacketAttackSignal(src=ExternalInput(), dst=ICMP()),
                            required_access_level="Proximity",
                        )
                    ],
                    # List of associated CPVs
                    "related_cpv": ["WiFiICMPFloodingCPV"],
                    # List of associated component-level attack effects
                    "comp_attack_effect": BaseCompEffect(
                        category="Availabilty",
                        description="Denial of Contro. The user cannot control the CPS.",
                    ),
                    # Steps of exploiting this attack vector
                    "exploit_steps": [
                        "Set the Wi-Fi card into monitor mode and find the BSSID and channel number for the CPS's Wi-Fi network.",
                        "Join the network.",
                        "Flood the CPS with TCP SYN on UDP port 5556.",
                    ],
                    # List of related references
                    "reference_urls": [
                        "https://link.springer.com/article/10.1007/s11416-011-0158-4"
                    ],
                },
                {
                    # List of related attack vectors and their exploitation information
                    "attack_vector": [
                        BaseAttackVector(
                            name="ARDiscovery DoS Flooding Attack",
                            signal=PacketAttackSignal(
                                src=ExternalInput(), dst=ARDiscovery()
                            ),
                            required_access_level="Proximity",
                        )
                    ],
                    # List of associated CPVs
                    "related_cpv": ["ARDiscoveryDoSCPV"],
                    # List of associated component-level attack effects
                    "comp_attack_effect": BaseCompEffect(
                        category="Availabilty",
                        description="Disrupts communication between the UAV and its controller, leading to operational failure or triggering fail-safe mechanisms (e.g., emergency landing).",
                    ),
                    # Steps of exploiting this attack vector
                    "exploit_steps": [
                        "Prepare the hardware: Ensure you have a Wi-Fi card capable of monitor mode and necessary tools (e.g., Scapy, Wireshark).",
                        "Scan the Wi-Fi network to identify the UAV's SSID using tools like `airodump-ng`.",
                        "Determine the UAV's channel and BSSID via network scanning tools.",
                        "Analyze the ARDiscovery protocol by capturing traffic using Wireshark and saving a sample ARDiscovery connection request packet.",
                        "Craft malicious packets with tools like Scapy to send excessive/malformed ARDiscovery requests to the UAV.",
                        "Flood the UAV with ARDiscovery packets by running a script that sends high-frequency requests.",
                        "Monitor the attack's effectiveness by checking if the UAV loses communication with the controller or enters fail-safe mode.",
                        "Optional: Post-exploitation—use the disruption to perform further analysis or intercept other communications.",
                    ],
                    # List of related references
                    "reference_urls": ["https://ieeexplore.ieee.org/document/7795496"],
                },
                {
                    # List of related attack vectors and their exploitation information
                    "attack_vector": [
                        BaseAttackVector(
                            name="ARDiscovery Buffer Overflow Attack",
                            signal=PacketAttackSignal(
                                src=ExternalInput(), dst=ARDiscovery()
                            ),
                            required_access_level="Proximity",
                        )
                    ],
                    # List of associated CPVs
                    "related_cpv": ["ARDiscoveryBufferOverflowCPV"],
                    # List of associated component-level attack effects
                    "comp_attack_effect": BaseCompEffect(
                        category="Availabilty",
                        description="Denial of Service. Causes the UAV to crash or exhibit undefined behavior, disrupting operations.",
                    ),
                    # Steps of exploiting this attack vector
                    "exploit_steps": [
                        "Prepare the hardware and tools: Ensure you have a Wi-Fi card and install required tools like Scapy and Wireshark.",
                        "Capture and analyze ARDiscovery packets using Wireshark to understand the protocol's structure.",
                        "Craft a malicious packet with an oversized payload that exceeds the ARDiscovery protocol's buffer size.",
                        "Use Scapy to send the crafted packet to the UAV over its Wi-Fi network.",
                        "Observe the UAV's behavior to verify a crash or unexpected response, such as rebooting or freezing.",
                        "Optional: Explore if remote code execution is possible by embedding shellcode in the payload.",
                    ],
                    # List of related references
                    "reference_urls": ["https://ieeexplore.ieee.org/document/7795496"],
                },
                {
                    # List of related attack vectors and their exploitation information
                    "attack_vector": [
                        BaseAttackVector(
                            name="Beacon Frame Flooding",
                            signal=PacketAttackSignal(src=ExternalInput(), dst=Wifi()),
                            required_access_level="Proximity",
                        )
                    ],
                    # List of associated CPVs
                    "related_cpv": ["BeaconFrameFloodingCPV"],
                    # List of associated component-level attack effects
                    "comp_attack_effect": BaseCompEffect(
                        category="Availabilty",
                        description="Denial of Service. Prevents the UAV from associating with its controller by overwhelming it with beacon frames.",
                    ),
                    # Steps of exploiting this attack vector
                    "exploit_steps": {
                        "TA1 Exploit Steps": [
                            "Install the ModWifi framework and aircrack-ng suite.",
                            "Set the Wi-Fi interface to monitoring mode.",
                            "Use airodump-ng to identify the target UAV's Wi-Fi network parameters, including:",
                            "    - SSID",
                            "    - Channel",
                            "    - BSSID",
                            "Capture and analyze the following settings in legitimate beacon frames using Wireshark or airodump-ng:",
                            "    - WMM settings",
                            "    - TIM (Traffic Indication Map) elements",
                            "    - Transmission power constraints",
                        ],
                        "TA2 Exploit Steps": [
                            "Craft malicious beacon frames with manipulated parameters, including:",
                            "    - Malicious power constraint values",
                            "    - Country information elements",
                            "    - Power constraint IEs along with Cisco Dynamic Transmit Power Control IE",
                            "Construct malicious beacons with extreme EDCA parameters based on extracted WMM update counts.",
                            "Modify TIM elements to indicate buffered frames waiting for all clients.",
                            "Create malicious beacons with Channel Switch Announcement (CSA) elements.",
                            "Ensure all attack payloads can be injected through the ModWifi framework.",
                        ],
                        "TA3 Exploit Steps": [
                            "Inject forged beacon frames after legitimate ones using the ModWifi framework.",
                            "Monitor UAV responses using airodump-ng or Wireshark.",
                            "Measure network performance changes using iperf3.",
                            "Verify the attack effects on:",
                            "    - Transmission power",
                            "    - Network throughput",
                            "    - Battery consumption",
                            "    - Channel switching",
                        ],
                    },
                    # List of related references
                    "reference_urls": [
                        "https://medium.com/@angelinatsuboi/drone-swarmer-uncovering-vulnerabilities-in-open-drone-id-cdd8d1a23c2c",
                        "https://dl.acm.org/doi/pdf/10.1145/3395351.3399442?casa_token=x2LV35bFGowAAAAA:X9TRtxKCpHQtY1ooiZgr4xszKrAUNb0_7m4JWLMjW-Ttr4Rxc-wtyRysnF4qD03ivfbX3W5OsVLSpQ",
                    ],
                },
            ],
        )

    def _vulnerable_components(self, device: Device) -> Iterator[ComponentID]:
        # Iterate through all components of the device
        for comp_id, comp in device.components.items():
            # Check if the component has supported protocols
            if (
                supported_protocols := comp.parameters.get("supported_protocols")
            ) is not None:
                # Iterate through the supported protocols
                for protocol in supported_protocols:
                    # Check if any protocol is unauthenticated, indicating a vulnerability
                    if issubclass(protocol, UnauthenticatedCommunication):
                        yield comp_id  # Vulnerability detected

    def exists(self, device: Device) -> bool:
        return any(True for _ in self._vulnerable_components(device))

    def effects(self, device: Device) -> list[VulnerabilityEffect]:
        return [
            MakeEntryEffect(
                reason="Unauthenticated Wifi",
                nodes=frozenset(self._vulnerable_components(device)),
            )
        ]
