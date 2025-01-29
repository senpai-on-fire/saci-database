import os.path

from clorm import Predicate

from saci.modeling import SpoofingtVulnerability

from saci.modeling.device import Device
from saci.modeling.device.sensor import Gyroscope, GyroscopeHWPackage 

from saci.modeling.communication import AuthenticatedCommunication, UnauthenticatedCommunication, ExternalInput

# Predicate to define formal reasoning logic for Gyroscope spoofing attacks
class GyroscopeSpoofingPred(Predicate):
    pass

class GyroscopeSpoofingVuln(SpoofingtVulnerability):
    def __init__(self):
        super().__init__(
            # The Gyroscope component vulnerable to spoofing attacks
            component=Gyroscope(),
            # Input: Authenticated communication representing spoofed signals from an external source
            _input=AuthenticatedCommunication(src=ExternalInput()),
            # Output: Authenticated communication representing erroneous navigation decisions caused by Gyroscope data
            output=AuthenticatedCommunication(),
            # Predicate for formal reasoning about Gyroscope spoofing
            attack_ASP=GyroscopeSpoofingPred,
            # Logic rules for evaluating the Gyroscope spoofing vulnerability
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'gyroscope_spoofing.lp'),
            # List of Associated CWEs:
            associated_cwe = [
                "CWE-346: Origin Validation Error",
                "CWE-290: Authentication Bypass by Capture-replay",
                "CWE-20: Improper Input Validation",
                "CWE-693: Protection Mechanism Failure",
                "CWE-1188: Insecure Default Initialization of Resource",
                "CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer",
                "CWE-662: Improper Synchronization"
            ]

        )

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            if isinstance(comp, Gyroscope) and comp.chip_type == "MEMS":
                return True

            if isinstance(comp, GyroscopeHWPackage):
                vuln_sensor_list = ['L3G4200D', 'L3GD20', 'LSM330', 'LPR5150AL', 'LPY503AL', 'MPU3050', 'MPU6000', 'MPU6050', 'MPU6500', 'MPU9150', 'IMU3000', 'ITG3200', 'IXZ650', 'ADXRS610', 'ENC-03MB']
                if comp.chip_name in vuln_sensor_list:
                    return True
        