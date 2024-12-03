import os.path

from clorm import Predicate

from saci.modeling.vulnerability import BaseVulnerability
from saci.modeling.device import Device
from saci.modeling.device.controller import ControllerHigh
from saci.modeling.communication import UnauthenticatedCommunication

class WeakDataIntegrityPred(Predicate):
    pass

class WeakDataIntegrityVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            # Assuming that ControllerHigh can represent a controller component (e.g., Rover or Quadcopter controller)
            component=ControllerHigh(),
            # Assuming the input is unauthenticated data received from spoofed sensors (e.g., gps or compass)
            _input=UnauthenticatedCommunication(),
            # the output will be faulty and unauthenticated control signals that will be passed to actuators (e.g., motors)
            output=UnauthenticatedCommunication(),
            attack_ASP=WeakDataIntegrityPred,
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'weakdataintegrity.lp')
        )

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            # Check if the component is a controller and whether it uses an integrity checking mechanism (e.g., EKF fusion)
            if isinstance(comp, ControllerHigh) and (comp.has_integrity_check == False):
                # TODO: what should we further check?
                return True
        return False
