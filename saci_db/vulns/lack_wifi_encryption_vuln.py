import os.path
from clorm import Predicate

from saci.modeling.attack import BaseCompEffect
from saci.modeling import BaseVulnerability
from saci.modeling.device import Device, Wifi, ARDiscovery, SikRadio
from saci.modeling.attack.radio_attack_signal import RadioAttackSignal
from saci.modeling.communication import AuthenticatedCommunication, UnauthenticatedCommunication, ExternalInput
from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector

# Predicate to define formal reasoning logic for WiFi vulnerabilities caused by a lack of data integrity or encryption
class LackWifiIntegrityPred(Predicate):
    pass

class LackWifiEncryptionVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            # The Wifi component is vulnerable due to the lack of proper encryption or integrity mechanisms
            component=Wifi(),
            # Input: Unauthenticated communication exploited to inject or alter data
            _input=UnauthenticatedCommunication(src=ExternalInput()),
            # Output: Unauthenticated communication representing altered or compromised WiFi data
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about vulnerabilities caused by a lack of WiFi integrity or encryption
            attack_ASP=LackWifiIntegrityPred,
            # Logic rules for evaluating this vulnerability in formal reasoning
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'lack_wifi_integrity.lp'),
            # List of Associated CWEs:
            associated_cwe = [
                "CWE-311: Missing Encryption of Sensitive Data",
                "CWE-319: Cleartext Transmission of Sensitive Information",
                "CWE-345: Insufficient Verification of Data Authenticity",
                "CWE-294: Authentication Bypass by Capture-replay",
                "CWE-326: Inadequate Encryption Strength",
                "CWE-20: Improper Input Validation",
                "CWE-1188: Insecure Default Initialization of Resource"
            ],
            attack_vectors_expoits = [
                {
                    # List of related attack vectors and their exploitation information”
                    "attack_vector": BaseAttackVector(name="Deauthentification Wifi Packets Injection", 
                                               signal=PacketAttackSignal(src=ExternalInput(), dst=Wifi()),
                                               required_access_level="Proximity",
                                               #  aireplay-ng -0 0 -a [BSSID] [interface_name]
                                               configuration={"BSSID":"FuelSource Wifi","interface_name":"wireless","other args":"-0 0 -a"}),
                    # List of associated CPVs”
                    "related_cpv": ['WiFiICMPFloodingCPV', 'WiFiDeauthQuadDosCPV'],
                    # List of associated component-level attack effects”
                    "comp_attack_effect": BaseCompEffect(category='Availability', description='Manipute management frames to disrupt network availability'),
                    # Steps of exploiting this attack vector”
                    "exploit_steps": ["Set the Wi-Fi card into monitor mode and find the BSSID and channel number for the CPS's Wi-Fi network.",
                                      "join the network",
                                      "Flood the CPS with TCP SYN on port UDP 5556"],
                    # List of related references”
                    "reference_urls": ["https://link.springer.com/article/10.1007/s11416-011-0158-4",
                                       "https://docs.google.com/document/d/1DB4kHnwS-eE6Yy0G1dbc3fyc5Q4_A2Yz/edit",
                                       "https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8658279&tag=1"]
                },
                
                {
                    "attack_vector": BaseAttackVector(
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
                ),
                    "related_cpv": ['ARDiscoveryDoSCPV'],
                    "comp_attack_effect": BaseCompEffect(category='Availability', description='Disrupts communication between the UAV and its controller, leading to operational failure or triggering fail-safe mechanisms (e.g., emergency landing).'),
                    "exploit_steps": [
                                        "Prepare the hardware: Ensure you have a Wi-Fi card capable of monitor mode and necessary tools (e.g., Scapy, Wireshark).",
                                        "Scan the Wi-Fi network to identify the UAV's SSID using tools like `airodump-ng`.",
                                        "Determine the UAV's channel and BSSID via network scanning tools.",
                                        "Analyze the ARDiscovery protocol by capturing traffic using Wireshark and saving a sample ARDiscovery connection request packet.",
                                        "Craft malicious packets with tools like Scapy to send excessive/malformed ARDiscovery requests to the UAV.",
                                        "Flood the UAV with ARDiscovery packets by running a script that sends high-frequency requests.",
                                        "Monitor the attack's effectiveness by checking if the UAV loses communication with the controller or enters fail-safe mode.",
                                        "Optional: Post-exploitation—use the disruption to perform further analysis or intercept other communications."],
                    "reference_urls": ['https://ieeexplore.ieee.org/document/7795496']
                },
                
                {
                    "attack_vector": BaseAttackVector(
                                        name="ARDiscovery Buffer Overflow Attack",
                                        signal=PacketAttackSignal(
                                            src=ExternalInput(),
                                            dst=ARDiscovery(),
                                        ),
                                        required_access_level="Proximity",
                                        configuration={
                                            "target_protocol": "ARDiscovery",
                                            "packet_size": "Exceeds buffer limit",
                                            "interface_name": "wireless",
                                            "attack_args": "Oversized payload with malicious data",
                                        },
                                    ),
                    "related_cpv": ['ARDiscoveryBufferOverflowCPV'],
                    "comp_attack_effect": BaseCompEffect(category='Integrity', description='Causes the UAV to crash or exhibit undefined behavior, disrupting operations.'),
                    "exploit_steps": [
                                        "Prepare the hardware and tools: Ensure you have a Wi-Fi card and install required tools like Scapy and Wireshark.",
                                        "Capture and analyze ARDiscovery packets using Wireshark to understand the protocol's structure.",
                                        "Craft a malicious packet with an oversized payload that exceeds the ARDiscovery protocol's buffer size.",
                                        "Use Scapy to send the crafted packet to the UAV over its Wi-Fi network.",
                                        "Observe the UAV's behavior to verify a crash or unexpected response, such as rebooting or freezing.",
                                        "Optional: Explore if remote code execution is possible by embedding shellcode in the payload."],
                    "reference_urls": ["https://ieeexplore.ieee.org/document/7795496"]
                },
                
                {
                    "attack_vector": BaseAttackVector(
                                        name="ARP Cache Poisoning Attack",
                                        signal=PacketAttackSignal(
                                            src=ExternalInput(),
                                            dst=ARDiscovery(),
                                        ),
                                        required_access_level="Proximity",
                                        configuration={
                                            "attack_method": "Spoofed ARP packets",
                                            "frequency": "High",
                                            "target": "UAV Wi-Fi interface",
                                        },
                                    ),
                    "related_cpv": ['ARDiscoveryMitM'],
                    "comp_attack_effect": BaseCompEffect(category='Integrity', description='Inject malicious ARP packets into the ARDiscovery protocol.'),
                    "exploit_steps": [
                                        "Scan the target Wi-Fi network to identify the UAV's IP and MAC address.",
                                        "Craft malicious ARP packets to associate the attacker's MAC address with the UAV's IP address.",
                                        "Send the spoofed ARP packets to poison the ARP cache of both the UAV and the controller.",
                                        "Capture and analyze the intercepted communication using tools like Wireshark.",
                                        "Optionally, inject malicious commands or modify the intercepted data to manipulate UAV behavior.",],
                    "reference_urls": ["https://ieeexplore.ieee.org/document/7795496"]
                },
                
                {
                    "attack_vector": BaseAttackVector(
                                        name="RF Jamming Attack",
                                        signal=RadioAttackSignal(
                                            src=ExternalInput(),
                                            dst=SikRadio(),
                                        ),
                                        required_access_level="Proximity",
                                        configuration={
                                            "attack_method": "Broadband RF jamming",
                                            "frequency_range": "2.4 GHz or 5 GHz",
                                            "hardware": "HackRF",
                                            "target": "UAV communication channel",
                                        }),
                    "related_cpv": ['RFJammingCPV'],
                    "comp_attack_effect": BaseCompEffect(category='Availability', description='Disrupts telemetry and control signals, causing the UAV to lose communication with its controller.'),
                    "exploit_steps": [
                                        "Identify the communication frequencies used between the Ground Control Station (GCS) and the drone running ArduPilot.",
                                        "Common frequency bands include:",
                                        "    - 2.4 GHz (Wi-Fi, telemetry control).",
                                        "    - 5.8 GHz (video transmission).",
                                        "Use software-defined radio (SDR) tools such as HackRF One or RTL-SDR to analyze real-time frequency spectrums.",
                                        "Select and configure appropriate RF jamming equipment based on identified frequencies.",
                                        "    - Choose between omnidirectional or directional jammers depending on the target environment.",
                                        "    - Adjust transmission power to effectively disrupt the drone-GCS link while minimizing unintended interference.",
                                        "Deploy the jammer within range of the drone’s operational zone to maximize disruption effectiveness.",
                                        "Activate the jammer and observe the drone’s behavior in response to communication loss.",
                                        "Monitor potential outcomes based on fail-safe configurations, including:",
                                        "    - Hovering in place due to loss of command signals.",
                                        "    - Initiating return-to-home (RTH) mode if GPS is available.",
                                        "    - Forced landing if the drone enters failsafe mode.",
                                        "Record the impact on network performance using iperf3 to measure throughput disruptions.",
                                        "Verify the jamming effects by analyzing telemetry dropouts and link quality reduction using tools like airodump-ng or Wireshark.",
                        ],
                    "reference_urls": ["https://d-fendsolutions.com/blog/types-of-jammers/",
                                       "https://d-fendsolutions.com/blog/suitability-of-jammers-for-rogue-drone-mitigation-at-airports/",
                                       "https://d-fendsolutions.com/blog/when-a-drone-is-jammed/",
                                       "https://media.defcon.org/DEF%20CON%2024/DEF%20CON%2024%20presentations/DEF%20CON%2024%20-%20Aaron-Luo-Drones-Hijacking-Multi-Dimensional-Attack-Vectors-And-Countermeasures-UPDATED.pdf"]
                },
                
                {
                    "attack_vector": [
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
                    "related_cpv": ['FTPTelnetHijackCPV'],
                    "comp_attack_effect": [BaseCompEffect(category='Availability', description='The user cannot stop or control the drone after deauthentication.'),
                                           BaseCompEffect(category='Integrity', description='The attacker gains root access via Telnet, enabling system-level manipulations.')],
                    "exploit_steps": [
                                        "Set the Wi-Fi card into monitor mode and locate the drone's BSSID and channel.",
                                        "Send continuous deauthentication packets to disconnect the legitimate controller.",
                                        "Establish a Telnet session to gain root access to the drone.",
                                        "Access the FTP service to extract data or modify critical files.",
                                        "Optionally modify the drone's configuration to disrupt its operations or cause a crash."
                                    ],
                    "reference_urls": ["https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8326960"]
                }
            ]
        )

    def exists(self, device: Device) -> bool:
        """
        Checks if the WiFi module lacks authentication mechanisms.
        The vulnerability exists if:
        - The WiFi module supports an **open network** (no password or authentication).
        - The network allows **unauthenticated** connections.
        - The device does not require **mutual authentication** for command transmission.
        """
        for comp in device.components:
            if isinstance(comp, Wifi):
                if comp.encryption_type in [None, "Open"]:
                    return True  # No authentication = vulnerable
                if not comp.requires_mutual_authentication:
                    return True  # No mutual authentication = vulnerable
        return False