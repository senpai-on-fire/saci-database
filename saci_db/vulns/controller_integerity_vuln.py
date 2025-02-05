import os.path
from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling.device import Device, Controller
from saci.modeling.state.operation_mode import OperationMode
from saci.modeling.communication import AuthenticatedCommunication, ExternalInput

from saci_db.devices.px4_quadcopter_device import PX4Controller

# Predicate to define formal reasoning for controller integrity attacks
class ControllerIntegrityPred(Predicate):
    pass

class ControllerIntegrityVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            # Components vulnerable to integrity manipulation: generic Controller and PX4Controller
            component=[Controller(), PX4Controller()],
            # Input: Even though communication is authenticated, the attacker manipulates the data before it reaches the controller
            _input=AuthenticatedCommunication(),
            # Output: Authenticated communication containing manipulated or corrupted data
            output=AuthenticatedCommunication(),
            # Predicate for formal reasoning about controller integrity vulnerabilities
            attack_ASP=ControllerIntegrityPred,
            # Logic rules for evaluating the controller integrity vulnerability
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'controller_integrity.lp'),
            # List of Associated CWEs:
            associated_cwe = [
                "CWE-20: Improper Input Validation",
                "CWE-502: Deserialization of Untrusted Data",
                "CWE-345: Insufficient Verification of Data Authenticity",
                "CWE-693: Protection Mechanism Failure",
                "CWE-925: Improper Verification of Integrity Check Value"
            ]


        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            if isinstance(comp, Controller) and comp.operating_mode in [OperationMode.MISSION, OperationMode.AUTONOMOUS]:
                # Check if the controller relies on a single vulnerable sensor
                if not comp.parameters['has_integrity_check']:
                    return True
        return False
