import os.path
from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling.device import Device, Serial
from saci.modeling.communication import UnauthenticatedCommunication
from saci.modeling.communication.protocol import UARTProtocol, I2CProtocol, SPIProtocol

class SerialSpoofingPred(Predicate):
    pass

class SerialSpoofingVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            component=Serial(),
            _input=UnauthenticatedCommunication(),
            output=UnauthenticatedCommunication(),
            attack_ASP=SerialSpoofingPred,
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'serial_spoofing.lp')
        )

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            if hasattr(comp, 'supported_protocols'):
                supported_protocols = comp.supported_protocols
                for protocol in supported_protocols:
                    if issubclass(protocol, UARTProtocol) or issubclass(protocol, I2CProtocol) or issubclass(protocol, SPIProtocol):
                        return True
        return False