import os.path

from clorm import Predicate

from saci.modeling.vulnerability import BaseVulnerability
from saci.modeling.device import Device, TelemetryHigh, WebServerHigh
from saci.modeling.communication import UnauthenticatedCommunication

class WeakApplicationAuthPred(Predicate):
    pass

class WeakApplicationAuthVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            # Assuming that TelemetryHigh can represent a communication component (webserver?) # TODO: How should we model it?
            component=WebServerHigh, # TODO: We should model the webserver
            # The input is unauthenticated HTTP GET requests
            _input=UnauthenticatedCommunication(),
            # The input is unauthenticated HTTP GET requests
            output=UnauthenticatedCommunication(),
            attack_ASP=WeakApplicationAuthPred,
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'weakapplicationauth.lp')
        )

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            # Check if the component is either a Webserver or and whether it uses http unautneticated http protocol
            if isinstance(comp, WebServerHigh) and comp.protocol_name == "http":
                return True
                # TODO: what should we further check?
        return False