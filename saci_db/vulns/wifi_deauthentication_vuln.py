"""
Modeling the deauthentication attack described in the research article:
https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8658279

Actual impacts:
- The CX-10W drone fell out of the sky.
- The Parrot AR drone performed an emergency landing procedure.

Modeled impact:
- Emergency landing procedure triggered after WiFi disconnection.
"""

import os.path

from clorm import Predicate

from saci.modeling import PublicSecretVulnerability
from saci.modeling.device import Device, Telnet, FTP
from saci.modeling.device import Wifi
from saci.modeling.communication import (
    UnauthenticatedCommunication,
    ExternalInput,
)
from saci.modeling.attack import BaseCompEffect
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.packet_attack_signal import PacketAttackSignal


# Predicate to define formal reasoning logic for WiFi deauthentication attacks
class WiFiDeauthPred(Predicate):
    pass


class WiFiDeauthVuln(PublicSecretVulnerability):
    def __init__(self):
        super().__init__(
            # The vulnerable component is the WiFi module
            component=Wifi(),
            # Input: Unauthenticated communication exploited to send deauthentication frames
            _input=UnauthenticatedCommunication(src=ExternalInput()),
            # Output: Unauthenticated communication leading to disconnection from the network
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about WiFi deauthentication attacks
            attack_ASP=WiFiDeauthPred,
            # Logic rules for evaluating vulnerabilities to deauthentication attacks
            rulefile=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "wifi_deauth.lp"
            ),
            # List of Associated CWEs:
            associated_cwe=[
                "CWE-770: Allocation of Resources Without Limits or Throttling",
                "CWE-400: Uncontrolled Resource Consumption",
                "CWE-294: Authentication Bypass by Capture-replay",
                "CWE-287: Improper Authentication",
                "CWE-20: Improper Input Validation",
                "CWE-1188: Insecure Default Initialization of Resource",
                "CWE-693: Protection Mechanism Failure",
            ],
            attack_vectors=[
                {
                    # List of related attack vectors and their exploitation information”
                    "attack_vector": [
                        BaseAttackVector(
                            name="Deauthentication WiFi Packets Injection",
                            signal=PacketAttackSignal(src=ExternalInput(), dst=Wifi()),
                            required_access_level="Proximity",
                        )
                    ],
                    # List of associated CPVs”
                    "related_cpv": ["WiFiDeauthQuadDosCPV"],
                    # List of associated component-level attack effects
                    "comp_attack_effect": BaseCompEffect(
                        category="Avialability",
                        description="Denial of Control. The user cannot stop the CPS",
                    ),
                    # Steps of exploiting this attack vector
                    "exploit_steps": [
                        "Set the Wi-Fi card into monitor mode and find the BSSID and channel number for the CPS's Wi-Fi network.",
                        "Send a deauthentication packet to the WIFI Interface.",
                    ],
                    # List of related references
                    "reference_urls": [
                        "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/blob/main/CPV001",
                        "https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8658279&tag=1",
                    ],
                },
                {
                    # Attack vector: Deauthentication Attack to Hijack Control
                    "attack_vector": [
                        BaseAttackVector(
                            name="Deauthentication Attack to Hijack Control",
                            signal=PacketAttackSignal(src=ExternalInput(), dst=Wifi()),
                            required_access_level="Proximity",
                        )
                    ],
                    # List of associated CPVs
                    "related_cpv": ["FTPTelnetHijackCPV"],
                    # List of associated component-level attack effects
                    "comp_attack_effect": BaseCompEffect(
                        category="Avialability",
                        description="Denial of Control.The user cannot stop or control the drone after deauthentication.",
                    ),
                    # Steps of exploiting this attack vector
                    "exploit_steps": [
                        "Set the Wi-Fi card into monitor mode and locate the drone's BSSID and channel.",
                        "Send continuous deauthentication packets to disconnect the legitimate controller.",
                    ],
                    # List of related references
                    "reference_urls": [
                        "https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8326960"
                    ],
                },
                {
                    # Attack vector: Telnet Access for Root Control
                    "attack_vector": [
                        BaseAttackVector(
                            name="Telnet Access for Root Control",
                            signal=PacketAttackSignal(
                                src=ExternalInput(), dst=Telnet()
                            ),
                            required_access_level="Proximity",
                        )
                    ],
                    # List of associated CPVs
                    "related_cpv": ["FTPTelnetHijackCPV"],
                    # List of associated component-level attack effects
                    "comp_attack_effect": BaseCompEffect(
                        category="Integrity",
                        description="Manipulation of Control. The attacker gains root access via Telnet, enabling system-level manipulations.",
                    ),
                    # Steps of exploiting this attack vector
                    "exploit_steps": [
                        "Identify the drone's open Telnet port using a network scanner.",
                        "Attempt default credentials or exploit misconfigurations to gain access.",
                        "Escalate privileges to root, if necessary.",
                        "Modify system files or settings to maintain persistent access.",
                    ],
                    # List of related references
                    "reference_urls": [
                        "https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8326960"
                    ],
                },
                {
                    # Attack vector: FTP Exploitation to Extract Data
                    "attack_vector": [
                        BaseAttackVector(
                            name="FTP Exploitation to Extract Data",
                            signal=PacketAttackSignal(src=ExternalInput(), dst=FTP()),
                            required_access_level="Proximity",
                        )
                    ],
                    # List of associated CPVs
                    "related_cpv": ["FTPTelnetHijackCPV"],
                    # List of associated component-level attack effects
                    "comp_attack_effect": BaseCompEffect(
                        category="Confidentiality",
                        description="Data Exfiltration. The attacker exploits FTP to extract data or modify critical files.",
                    ),
                    # Steps of exploiting this attack vector
                    "exploit_steps": [
                        "Scan for an open FTP service on the drone.",
                        "Attempt login using default credentials or exploit vulnerabilities.",
                        "Extract sensitive logs, flight data, or modify configuration files.",
                    ],
                    # List of related references
                    "reference_urls": [
                        "https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8326960"
                    ],
                },
            ],
        )

    def exists(self, device: Device) -> bool:
        """
        Checks if the WiFi module is vulnerable to deauthentication attacks.
        The vulnerability exists if:
        - The WiFi module does not support Management Frame Protection (MFP).
        - The network is **open** or **uses WPA2 without MFP**.
        - The network allows unprotected disassociation requests.
        """
        for comp in device.components:
            if isinstance(comp, Wifi):
                if comp.encryption_type in [None, "WEP", "Open"]:
                    return True  # Open or weak encryption = vulnerable
                if (
                    comp.encryption_type == "WPA2"
                    and not comp.has_management_frame_protection
                ):
                    return True  # WPA2 without MFP = vulnerable
        return False
