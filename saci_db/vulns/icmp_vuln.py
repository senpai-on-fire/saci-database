import os.path

from clorm import Predicate

from saci.modeling import PublicSecretVulnerability
from saci.modeling.device import Device, Telemetry, ICMP
from saci.modeling.communication import UnauthenticatedCommunication

class IcmpFloodPred(Predicate):
    pass

class IcmpFloodVuln(PublicSecretVulnerability):
    def __init__(self):
        super().__init__(
            # Assuming that TelemetryHigh can represent a network component
            component=ICMP(),
            # The input to an ICMP flood attack is unauthenticated
            _input=UnauthenticatedCommunication(),
            # The output is network disruption due to the unauthenticated ICMP flood
            output=UnauthenticatedCommunication(),
            attack_ASP=IcmpFloodPred,
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'icmp_flood.lp')
        )

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            # Check if the component uses the ICMP protocol
            if isinstance(comp, Telemetry) and comp.protocol_name == "icmp":
                # If ICMP is present, we assume it's vulnerable to ICMP flood attacks
                return True
        return False