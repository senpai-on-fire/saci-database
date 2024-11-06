import os.path

from clorm import Predicate

from saci.modeling import PublicSecretVulnerability, BaseVulnerability
from saci.modeling.device import Device, TelemetryHigh
from saci.modeling.communication import UnauthenticatedCommunication, AuthenticatedCommunication
from saci.modeling.device.motor.steering import SteeringHigh

class NoAPSPred(Predicate):
    pass

class NoAPSVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            component=SteeringHigh(),
            # The input is...?
            _input=UnauthenticatedCommunication(),
            # The output is...?
            output=None,
            attack_ASP=NoAPSPred,
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'noaps.lp')
        )

    def exists(self, device: Device) -> bool:
        return any(isinstance(comp, SteeringHigh) and not comp.has_aps for comp in device.components)


