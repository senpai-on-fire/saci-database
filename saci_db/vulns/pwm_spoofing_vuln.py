import os.path

from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling.device import PWMChannel, Device
from saci.modeling.communication import UnauthenticatedCommunication

class PWMSpoofingPred(Predicate):
    pass

class PWMSpoofingVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            component=PWMChannel(),
            # Input here would be the unauthenticated, spoofed PWM signals
            _input=UnauthenticatedCommunication(),
            # Output would be erroneous commands to the ESC (for speed control)
            output=UnauthenticatedCommunication(),
            attack_ASP=PWMSpoofingPred,
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'pwm_spoofing.lp')
        )

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            return True            
        return False

