import os.path
from clorm import Predicate

from saci.modeling import SpoofingVulnerability
from saci.modeling.device import Device, Serial
from saci.modeling.communication import AuthenticatedCommunication, UnauthenticatedCommunication, ExternalInput
from saci.modeling.communication.protocol import UARTProtocol, I2CProtocol, SPIProtocol

# Predicate to define formal reasoning logic for serial spoofing attacks
class SerialSpoofingPred(Predicate):
    pass

class SerialSpoofingVuln(SpoofingVulnerability):
    def __init__(self):
        super().__init__(
            # The Serial component is vulnerable to spoofing attacks
            component=Serial(),
            # Input: Unauthenticated communication used to spoof serial data
            _input=UnauthenticatedCommunication(),
            # Output: Unauthenticated communication representing manipulated or spoofed serial data
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about serial spoofing vulnerabilities
            attack_ASP=SerialSpoofingPred,
            # Logic rules for evaluating serial spoofing vulnerabilities in formal reasoning
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'serial_spoofing.lp'),
            # List of Associated CWEs:
            associated_cwe = [
                "CWE-287: Improper Authentication",
                "CWE-294: Authentication Bypass by Capture-replay",
                "CWE-306: Missing Authentication for Critical Function",
                "CWE-345: Insufficient Verification of Data Authenticity",
                "CWE-20: Improper Input Validation",
                "CWE-1188: Insecure Default Initialization of Resource"
            ]
        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component supports serial communication protocols
            if hasattr(comp, 'supported_protocols'):
                supported_protocols = comp.supported_protocols
                # Iterate through the supported protocols
                for protocol in supported_protocols:
                    # Check if the protocol is UART, I2C, or SPI
                    if isinstance(protocol, UARTProtocol) or isinstance(protocol, I2CProtocol) or isinstance(protocol, SPIProtocol):
                        return True  # Vulnerability exists if a supported protocol is found
        return False  # No vulnerability detected if no matching protocols are found
