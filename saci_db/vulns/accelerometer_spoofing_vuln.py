import os.path

from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling import SpoofingtVulnerability
from saci.modeling.device import Device
from saci.modeling.device.sensor.accelerometer import Accelerometer
from saci.modeling.communication import UnauthenticatedCommunication, AuthenticatedCommunication, ExternalInput

# Predicate to define the formal reasoning logic for the accelerometer spoofing attack
class AccelerometerSpoofingPred(Predicate):
    pass

class AccelerometerSpoofingVuln(SpoofingtVulnerability):
    def __init__(self):
        super().__init__(
            # The accelerometer component that is vulnerable to spoofing attacks
            component=Accelerometer(),
            # Input to the spoofing attack: Authenticated, spoofed accelerometer signals
            _input=AuthenticatedCommunication(src=ExternalInput()),
            # Output: navigation decisions corrupted by the spoofed accelerometer signals
            output=AuthenticatedCommunication(),
            # Predicate for reasoning about accelerometer spoofing attacks
            attack_ASP=AccelerometerSpoofingPred,
            # Logic rules for evaluating this vulnerability
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'accelerometer_spoofing.lp'),
            # List of associated CWEs
            associated_cwe=[
                "CWE-346: Origin Validation Error",
                "CWE-290: Authentication Bypass by Capture-replay",
                "CWE-20: Improper Input Validation",
                "CWE-1188: Insecure Default Initialization of Resource",
                "CWE-693: Protection Mechanism Failure"
            ]
                      
        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is an accelerometer and its signals are unauthenticated
            if isinstance(comp, Accelerometer) and not comp.authenticated:
                return True  # Vulnerability exists if conditions are met
        return False  # Return False if no vulnerable accelerometer is found
