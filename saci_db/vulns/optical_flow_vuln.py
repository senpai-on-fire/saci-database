import os.path
from clorm import Predicate
from saci.modeling import BaseVulnerability
from saci.modeling.device import Device
from saci.modeling.device.optical_flow import OpticalFlowSensor
from saci.modeling.communication import UnauthenticatedCommunication

class OpticalFlowSpoofingPred(Predicate):
    pass

class OpticalFlowSpoofingVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            component=OpticalFlowSensor(),
            _input=UnauthenticatedCommunication(),
            output=UnauthenticatedCommunication(),
            attack_ASP=OpticalFlowSpoofingPred,
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'optical_flow_spoofing.lp')
        )

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            if isinstance(comp, OpticalFlowSensor) and comp.uses_corner_detection():
                return True
        return False