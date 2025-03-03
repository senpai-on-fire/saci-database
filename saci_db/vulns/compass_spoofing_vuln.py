import os.path

from clorm import Predicate

from saci.modeling.attack import BaseCompEffect
from saci.modeling import BaseVulnerability
from saci.modeling import SpoofingVulnerability
from saci.modeling.device import Device
from saci.modeling.device.sensor.compass import CompassSensor
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.magnetic_attack_signal import MagneticAttackSignal
from saci.modeling.communication import AuthenticatedCommunication, UnauthenticatedCommunication, ExternalInput

# Predicate to define formal reasoning logic for compass spoofing attacks
class CompassSpoofingPred(Predicate):
    pass

class CompassSpoofingVuln(SpoofingVulnerability):
    def __init__(self):
        super().__init__(
            # The CompassSensor component vulnerable to spoofing attacks
            component=CompassSensor(),
            # Input: Authenticated communication representing spoofed signals from an external source
            _input=AuthenticatedCommunication(src=ExternalInput()),
            # Output: Authenticated communication representing erroneous navigation decisions caused by spoofed compass data
            output=AuthenticatedCommunication(),
            # Predicate for formal reasoning about compass spoofing
            attack_ASP=CompassSpoofingPred,
            # Logic rules for evaluating the compass spoofing vulnerability
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'compass_spoofing.lp'),
            # List of Associated CWEs:
            associated_cwe = [
                "CWE-346: Origin Validation Error",
                "CWE-290: Authentication Bypass by Capture-replay",
                "CWE-20: Improper Input Validation",
                "CWE-693: Protection Mechanism Failure",
                "CWE-1188: Insecure Default Initialization of Resource"
            ],
            attack_vectors = [BaseAttackVector(name="Magnetic Signals Interference", 
                                               signal=MagneticAttackSignal(src=ExternalInput(), dst=CompassSensor()),
                                               required_access_level="Physical")],
            exploits=['CompassTemporarySpoofingCPV', 'CompassPermanentSpoofingCPV'],
            comp_attack_effect=BaseCompEffect(category='Integrity', description='Inject erroneous compass data'),
            reference_urls=["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV007",
                            "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV006"]
        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a CompassSensor
            if isinstance(comp, CompassSensor):
                return True  # Vulnerability exists if a CompassSensor is found
        return False  # No vulnerability detected if no CompassSensor is found
