import os

from clorm import Predicate, ConstantStr
from clorm.clingo import Control

from saci.modeling import PublicSecretVulnerability
from saci.modeling.device import TelemetryHigh, TelemetryAlgorithmic, Device
from saci.modeling.communication import AuthenticatedCommunication, ExternalInput

class SiK_Attack(Predicate):
    time: int

class SiKCPSV(PublicSecretVulnerability):
    def __init__(self):
        super().__init__(
            # TODO: how do you describe that it can occur in both Algorithmic and High telemetry?
            component=TelemetryAlgorithmic,
            # TODO: how to express input/output constraints
            _input=AuthenticatedCommunication(src=ExternalInput()),
            output=AuthenticatedCommunication(),
            attack_ASP=[SiK_Attack],
            rulefile=os.path.join(os.path.realpath(__file__), 'sik.lp')
        )

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            if isinstance(comp, TelemetryHigh) and comp.protocol_name == "sik":
                return True
