import os.path

from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling.device import GPSReceiver, Device
from saci.modeling.communication import UnauthenticatedCommunication

class GPSSpoofingPred(Predicate):
    pass

class GPSSpoofingVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            component=GPSReceiver(),
            # Input here would be the unauthenticated, spoofed GPS signals
            _input=UnauthenticatedCommunication(),
            # Output would be erroneous navigation decisions based on spoofed signals
            output=UnauthenticatedCommunication(),
            attack_ASP=GPSSpoofingPred,
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'gpsspoofing.lp')
        )

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            # Check if the device uses GPS for navigation and if the GPS signals are not authenticated
            if isinstance(comp, GPSReceiver) and not comp.authenticated:
                return True

        return False
