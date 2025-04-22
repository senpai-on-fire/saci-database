import os
from clorm import Predicate, IntegerField

from saci.modeling import PublicSecretVulnerability
from saci.modeling.device import Device, Mavlink
from saci.modeling.communication import AuthenticatedCommunication, UnauthenticatedCommunication, ExternalInput

class Attack_CPSV_Overflow(Predicate):
    time = IntegerField()

class MavlinkOverflow(PublicSecretVulnerability):
    def __init__(self):
        super().__init__(
            # TODO: how do you describe that it can occur in both Algorithmic and High telemetry?
            component=Mavlink(),
            # TODO: how to express input/output constraints
            _input=UnauthenticatedCommunication(src=ExternalInput()),
            output=UnauthenticatedCommunication(),
            attack_ASP=Attack_CPSV_Overflow,
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'mavlink_overflow.lp'),
            # List of Associated CWEs:
            associated_cwe = [
                "CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
                "CWE-125: Out-of-Bounds Read",
                "CWE-787: Out-of-Bounds Write",
                "CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer",
                "CWE-94: Improper Control of Generation of Code ('Code Injection')",
                "CWE-20: Improper Input Validation",
                "CWE-400: Uncontrolled Resource Consumption"],
            attack_vectors_exploits = []
        )
        #self.input = "overflow the mavlink protocol"

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            # if it's the Mavlink protocol we don't need to do any symbolic check since
            # we are already aware that it's vulnerable to this attack
            # if isinstance(comp, TelemetryHigh) and comp.protocol_name == "mavlink":
            if type(comp) is type(self.component):
                return True
