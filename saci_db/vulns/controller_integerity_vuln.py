import os.path
from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling.device import Device, ControllerHigh
from saci.modeling.state.operation_mode import OperationMode
from saci.modeling.communication import AuthenticatedCommunication


class ControllerIntegrityPred(Predicate):
    pass


class ControllerIntegrityVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            component=ControllerHigh(),
            # TODO: even the input is authenticated, the attacker manipulate the data before it reaches the controller
            _input=AuthenticatedCommunication(),
            output=AuthenticatedCommunication(),
            attack_ASP=ControllerIntegrityPred,
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'controller_integrity.lp')
        )

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            if isinstance(comp, ControllerHigh) and comp.operating_mode in [OperationMode.MISSION, OperationMode.AUTONOMOUS]:
                # Check if the controller relies on a single vulnerable sensor
                if not comp.has_integrity_check:
                    return True
        return False