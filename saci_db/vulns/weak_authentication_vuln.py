import os.path

from clorm import Predicate

from saci.modeling.vulnerability import BaseVulnerability
from saci.modeling.device import Device, TelemetryHigh
from saci.modeling.communication import UnauthenticatedCommunication

class WeakAuthenticationPred(Predicate):
    pass

class WeakAuthenticationVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            # Assuming that TelemetryHigh can represent a communication component 
            component=TelemetryHigh(),
            # The serial input command is unauthenticated 
            _input=UnauthenticatedCommunication(),
            # The output is another unauthenticated serial data
            output=UnauthenticatedCommunication(),
            attack_ASP=WeakAuthenticationPred,
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'weakauthentication.lp')
        )

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            # Check if the component is either a WIFI or Serial Telemetry and whether it uses vulnerable communication protocols
            if isinstance(comp, TelemetryHigh):
                if comp.type == "WiFi_Telemetry" and (comp.protocol_name == "WPA" or comp.protocol_name == "WEP"):
                    return True
                if comp.type == "WiFi_Serial" and (comp.protocol_name == "UART" or comp.protocol_name == "CAN" or comp.protocol_name == "SPI"):
                    return True
                # TODO: what should we further check?
        return False

