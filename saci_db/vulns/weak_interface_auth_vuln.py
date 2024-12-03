import os.path

from clorm import Predicate

from saci.modeling.vulnerability import BaseVulnerability
from saci.modeling.device import Device, TelemetryHigh
from saci.modeling.communication import UnauthenticatedCommunication

class WeakInterfaceAuthPred(Predicate):
    pass

class WeakInterfaceAuthVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            # Assuming that TelemetryHigh can represent a communication component (WIFI or Serial)
            component=TelemetryHigh(),
            # The serial/wireless input is unauthenticated 
            _input=UnauthenticatedCommunication(),
            # The serial/wireless output is also unauthenticated
            output=UnauthenticatedCommunication(),
            attack_ASP=WeakInterfaceAuthPred,
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'weakinterfaceauth.lp')
        )

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            # Check if the component is either a WIFI/Serial Telemetry and whether it uses vulnerable communication protocols
            if isinstance(comp, TelemetryHigh):
                if comp.type == "WiFi_Telemetry" and (comp.protocol_name == "WPA" or comp.protocol_name == "WEP"):
                    return True
                if comp.type == "WiFi_Serial" and (comp.protocol_name == "UART" or comp.protocol_name == "CAN" or comp.protocol_name == "SPI"):
                    return True
                # TODO: what should we further check?
        return False

