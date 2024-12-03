import os.path
from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling.device import Device, SerialAlgorithmic, WifiAlgorithmic
from saci.modeling.communication import UnauthenticatedCommunication

class LackAuthenticationPred(Predicate):
    pass

class LackAuthenticationVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            component=SerialAlgorithmic(),
            _input=UnauthenticatedCommunication(),
            output=UnauthenticatedCommunication(),
            attack_ASP=LackAuthenticationPred,
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'lack_authentication.lp')
        )

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            if hasattr(comp, 'supported_protocols'):
                supported_protocols = comp.supported_protocols
                for protocol in supported_protocols:
                    if issubclass(protocol, UnauthenticatedCommunication):
                        return True
        return False