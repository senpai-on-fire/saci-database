import os
from clorm import Predicate, IntegerField

from saci.modeling import PublicSecretVulnerability
from saci.modeling.device import TelemetryHigh, TelemetryAlgorithmic, Device, Mavlink
from saci.modeling.communication import AuthenticatedCommunication, UnauthenticatedCommunication, ExternalInput

class Attack_CPSV_Mavlink(Predicate):
    time = IntegerField()

class MavlinkMitmVuln(PublicSecretVulnerability):
    def __init__(self):
        super().__init__(
            # TODO: how do you describe that it can occur in both Algorithmic and High telemetry?
            component=Mavlink(),
            # TODO: how to express input/output constraints
            _input=UnauthenticatedCommunication(src=ExternalInput()),
            output=UnauthenticatedCommunication(),
            attack_ASP=Attack_CPSV_Mavlink,
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'mavlink_mitm.lp'),
            # List of Associated CWEs:
            associated_cwe=[
                "CWE-300: Channel Accessible by Non-Endpoint ('Man-in-the-Middle')",
                "CWE-345: Insufficient Verification of Data Authenticity",
                "CWE-441: Unintended Proxy or Intermediary ('Confused Deputy')",
                "CWE-294: Authentication Bypass by Capture-replay",
                "CWE-693: Protection Mechanism Failure"
            ],
            attack_vectors_exploits = []
        )
        #self.input = "launch a Mavlink MITM attack"

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            # if it's the Mavlink protocol we don't need to do any symbolic check since
            # we are already aware that it's vulnerable to this attack
            # if isinstance(comp, TelemetryHigh) and comp.protocol_name == "mavlink":
            if type(comp) is type(self.component):
                return True

            # check to see if we can achieve the following scenario:
            # 1. User A sends a packet, identifier is X
            # 2. User B sends a packer, identifier is also X
            # i.e., any case where two distinct users can get the same identifier is a vulnerability
            # (authentication failure)
            if isinstance(comp, TelemetryAlgorithmic):
                # TODO: how to express these properties could be symbolic? We essentially need a way to check
                #   that a telemetry can send an arbitrary constructed packet. For now, we just put a fake
                #   two packets there (always true for now)
                good_comm = AuthenticatedCommunication(src="192.168.1.2", dst="controller")
                bad_comm = AuthenticatedCommunication(src="192.168.1.3", dst="controller")
                if (good_comm.src != bad_comm.src) and (good_comm.identifier == bad_comm.identifier):
                    return True

