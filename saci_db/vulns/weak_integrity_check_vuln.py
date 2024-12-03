import os.path

from clorm import Predicate

from saci.modeling.vulnerability import BaseVulnerability
from saci.modeling.device import Device
from saci.modeling.device.controller import ControllerHigh
from saci.modeling.communication import UnauthenticatedCommunication

class WeakIntegritynPred(Predicate):
    pass

class WeakIntegrityVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            # Assuming that ControllerHigh can represent a controller component 
            component=ControllerHigh(),
            # Assuming the input is unauthenticated data received from spoofed sensors (e.g., gps or compass)
            _input=UnauthenticatedCommunication(),
            # the output will be faulty and unauthenticated control signals that will be passed to actuators (e.g., motors)
            output=UnauthenticatedCommunication(),
            attack_ASP=WeakIntegritynPred,
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'weakintegrity.lp')
        )

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            # Check if the component is a controller and whether it uses an integrity checking mechanism
            if isinstance(comp, ControllerHigh) and (comp.integrity_check == None):
                # TODO: what should we further check?
                return True
        return False
