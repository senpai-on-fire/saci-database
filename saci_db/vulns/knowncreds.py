import os.path

from clorm import Predicate

from saci.modeling import PublicSecretVulnerability
from saci.modeling.device import Device, TelemetryHigh, Telemetry
from saci.modeling.communication import UnauthenticatedCommunication, AuthenticatedCommunication
from saci.modeling.device.wifi import Wifi


class KnownCredsPred(Predicate):
    pass

class WifiKnownCredsVuln(PublicSecretVulnerability):
    def __init__(self):
        super().__init__(
            # Assuming that TelemetryHigh can represent a WiFi component
            component=Wifi(),
            # The input to a deauth attack is unauthenticated 
            _input=UnauthenticatedCommunication(),
            # The output is the disconnection 
            output=AuthenticatedCommunication(),
            attack_ASP=KnownCredsPred,
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'known_creds.lp')
        )

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            # Check if the component uses WiFi and is either unprotected or using WPA2 encryption
            if isinstance(comp, TelemetryHigh) and comp.protocol_name == "wifi":
                # TODO: check to see if we actually know the creds...
                return True
            if isinstance(comp, Wifi):
                return True
        return False


