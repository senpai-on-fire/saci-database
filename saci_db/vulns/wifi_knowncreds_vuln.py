import os.path

from clorm import Predicate

from saci.modeling import PublicSecretVulnerability
from saci.modeling.device import Device, Wifi, TelemetryHigh, Telemetry
from saci.modeling.communication import AuthenticatedCommunication, UnauthenticatedCommunication, ExternalInput
from saci.modeling.attack import BaseCompEffect
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.packet_attack_signal import PacketAttackSignal

# Predicate to define formal reasoning logic for vulnerabilities caused by known credentials
class KnownCredsPred(Predicate):
    pass

class WifiKnownCredsVuln(PublicSecretVulnerability):
    def __init__(self):
        super().__init__(
            # The vulnerable component is the WiFi module
            component=Wifi(),
            # Input: Unauthenticated communication representing attempts to exploit known credentials
            _input=UnauthenticatedCommunication(),
            # Output: Unauthenticated communication representing unauthorized disconnections or access
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about vulnerabilities caused by known credentials
            attack_ASP=KnownCredsPred,
            # Logic rules for reasoning about known credentials vulnerabilities
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'known_creds.lp'),
            # List of Associated CWEs:
            associated_cwe = [
                "CWE-798: Use of Hard-coded Credentials",
                "CWE-287: Improper Authentication",
                "CWE-521: Weak Password Requirements",
                "CWE-295: Improper Certificate Validation",
                "CWE-20: Improper Input Validation",
                "CWE-1188: Insecure Default Initialization of Resource",
                "CWE-345: Insufficient Verification of Data Authenticity",
                "CWE-308: Use of Single-factor Authentication"
            ],
            attack_vectors_exploits = [
                {
                    # List of related attack vectors and their exploitation information
                    "attack_vector": [BaseAttackVector(name="Stop Button Manipulation via HTTP Requests Injection",
                                                    signal=PacketAttackSignal(src=ExternalInput(), dst=Wifi()),
                                                    required_access_level="Proximity")],
                    
                    # List of associated CPVs
                    "related_cpv": ['WifiWebStopCPV'],

                    # List of associated component-level attack effects
                    "comp_attack_effect": BaseCompEffect(category="Integrity", 
                                                        description="Manipulation of Control. The CPS stops without the operator's input."),

                    # Steps of exploiting this attack vector
                    "exploit_steps": [
                        "Connect to the Wi-Fi network using the hardcoded credentials.",
                        "Using a web browser, navigate to the webserver IP address.",
                        "Observe that the CPS remains idle.",
                        "Click either of the drive buttons.",
                        "Ensure the rover begins to drive."
                    ],

                    # List of related references
                    "reference_urls": [
                        "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/blob/main/CPV009/HII-NGP1AROV1ARR03-CPV009-20240911.docx"
                    ]
                },
                {
                    # List of related attack vectors and their exploitation information
                    "attack_vector": [BaseAttackVector(name="Long HTTP GET Requests Injection",
                                                    # The external input will be the long HTTP request from the attacker's web client
                                                    signal=PacketAttackSignal(src=ExternalInput(), dst=Wifi()),
                                                    required_access_level="Proximity")],
                    
                    # List of associated CPVs
                    "related_cpv": ['WifiWebCrashCPV'],

                    # List of associated component-level attack effects
                    "comp_attack_effect": BaseCompEffect(category="Availability", 
                                                        description="Loss of Control. The user cannot stop the CPS while driving."),

                    # Steps of exploiting this attack vector
                    "exploit_steps": [
                        "Connect to the rover's Wi-Fi using hardcoded credentials.",
                        "Issue a long HTTP GET request (at least 26,000 characters) to the webserver address."
                    ],

                    # List of related references
                    "reference_urls": [
                        "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/blob/main/CPV003/HII-NGP1AROV1ARR03-CPV003-20240828.docx"
                    ]
                }
            ]

        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a TelemetryHigh module using WiFi
            if isinstance(comp, TelemetryHigh) and comp.protocol_name == "wifi":
                # Check if the credentials are known or weak (optional enhancement)
                if hasattr(comp, 'credentials') and comp.credentials in self.known_credentials():
                    return True  # Vulnerability exists if credentials are weak or known
            # Check if the component is a WiFi module
            if isinstance(comp, Wifi):
                # Further checks could be added here for specific attributes of the WiFi component
                return True  # Vulnerability exists for any unprotected or insecure WiFi module
        return False  # No vulnerability detected

    def known_credentials(self):
        """
        A helper method to return a list of known or weak credentials.
        This can be a static list or fetched dynamically from a database or configuration.
        """
        return ["admin:admin", "user:password", "12345678"]  # Example of weak credentials
