import os
from clorm import Predicate, IntegerField

from saci.modeling import PublicSecretVulnerability
from saci.modeling.device import TelemetryHigh, TelemetryAlgorithmic, Device
from saci.modeling.communication import AuthenticatedCommunication, ExternalInput

class Attack_CPSV_Mavlink(Predicate):
    time = IntegerField()

class MavlinkVuln01(PublicSecretVulnerability):
    def __init__(self):
        super().__init__(
            # TODO: how do you describe that it can occur in both Algorithmic and High telemetry?
            component=TelemetryAlgorithmic,
            # TODO: how to express input/output constraints
            _input=AuthenticatedCommunication(src=ExternalInput()),
            output=AuthenticatedCommunication(),
            attack_ASP=Attack_CPSV_Mavlink,
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'mavlink_mitm.lp')
        )

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            # if it's the Mavlink protocol we don't need to do any symbolic check since
            # we are already aware that it's vulnerable to this attack
            if isinstance(comp, TelemetryHigh) and comp.protocol_name == "mavlink":
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

