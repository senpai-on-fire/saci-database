import os.path

from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling.device import Device
from saci.modeling.device.compass import CompassSensor
from saci.modeling.communication import UnauthenticatedCommunication

class CompassSpoofingPred(Predicate):
    pass

class CompassSpoofingVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            component=CompassSensor(),
            # Input here would be the unauthenticated, spoofed compass signals
            _input=UnauthenticatedCommunication(),
            # Output would be erroneous navigation decisions based on spoofed compass signals (because of faulty heading data)
            output=UnauthenticatedCommunication(),
            attack_ASP=CompassSpoofingPred,
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'compass_spoofing.lp')
        )

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            # Check if the device uses a compass sensor for navigation (heading) and if the compass signals are not authenticated
            if isinstance(comp, CompassSensor) and not comp.authenticated:
                return True

        return False
