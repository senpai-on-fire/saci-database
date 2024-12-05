import os.path
from clorm import Predicate
from saci.modeling import BaseVulnerability
from saci.modeling.device import Device
from saci.modeling.device.depth_camera import DepthCamera
from saci.modeling.communication import UnauthenticatedCommunication

class DepthCameraSpoofingPred(Predicate):
    pass

class DepthCameraSpoofingVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            component=DepthCamera(),
            _input=UnauthenticatedCommunication(),
            output=UnauthenticatedCommunication(),
            attack_ASP=DepthCameraSpoofingPred,
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'depth_camera_spoofing.lp')
        )

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            if isinstance(comp, DepthCamera) and comp.supports_stereo_vision() and comp.enabled():
                return True
        return False