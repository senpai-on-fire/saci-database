'''''
Modeling the deauthentication attack https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8658279
Actual impacts: The CX-10W fell out of the sky, Parrot AR performed an emergency landing procedure.
The modeled impact is: emergency landing procedure after the disconnection. 
'''''
from saci.modeling import PublicSecretVulnerability
from saci.modeling.device import Device, TelemetryHigh
from saci.modeling.communication import UnauthenticatedCommunication

class WiFiDeauthVuln(PublicSecretVulnerability):
    def __init__(self):
        super().__init__(
            # Assuming that TelemetryHigh can represent a WiFi component
            component=TelemetryHigh(),
            # The input to a deauth attack is unauthenticated 
            _input=UnauthenticatedCommunication(),
            # The output is the disconnection 
            output=UnauthenticatedCommunication(),
        )

def exists(self, device: Device) -> bool:
    for comp in device.components:
        # Check if the component uses WiFi and is either unprotected or using WPA2 encryption
        if isinstance(comp, TelemetryHigh) and comp.protocol_name == "wifi":
            if comp.encryption_type == "WPA2" or comp.encryption_type is None:
                # If WPA2 is used without management frame protection or if there's no encryption, it's vulnerable
                return True
    return False


