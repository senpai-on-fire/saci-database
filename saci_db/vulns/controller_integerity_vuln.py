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
            component=Controller(),
            # Input: Even though communication is authenticated, the attacker manipulates the data before it reaches the controller
            _input=AuthenticatedCommunication(),
            # Output: Authenticated communication containing manipulated or corrupted data
            output=AuthenticatedCommunication(),
            # Predicate for formal reasoning about controller integrity vulnerabilities
            attack_ASP=ControllerIntegrityPred,
            # Logic rules for evaluating the controller integrity vulnerability
            rulefile=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "controller_integrity.lp"
            ),
            # List of Associated CWEs:
            associated_cwe=[
                "CWE-20: Improper Input Validation",
                "CWE-502: Deserialization of Untrusted Data",
                "CWE-345: Insufficient Verification of Data Authenticity",
                "CWE-693: Protection Mechanism Failure",
                "CWE-925: Improper Verification of Integrity Check Value",
            ],
            attack_vectors=[],
        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            if isinstance(comp, Controller) and comp.operating_mode in [
                OperationMode.MISSION,
                OperationMode.AUTONOMOUS,
            ]:
                # Check if the controller relies on a single vulnerable sensor
                if not comp.parameters["has_integrity_check"]:
                    return True

                # What should we add to describe Lack of Sensor Consistency Checks or Lack of Sensor Filtering?
                filter_type = comp.parameters.get(
                    "sensor_filter_type", "none"
                )  # Could be 'none', 'low_pass', or 'EKF'
                cross_sensor_consistency_checks = comp.parameters.get(
                    "cross_sensor_consistency_checks", False
                )

                # Define vulnerability conditions
                no_filtering = filter_type == "none"
                weak_filtering = filter_type == "low_pass"
                lacks_cross_sensor_consistency_checks = (
                    not cross_sensor_consistency_checks
                )

                # Controller is vulnerable if:
                # 1. It lacks integrity checks entirely
                # 2. It has weak or no filtering, allowing injected sensor noise to propagate
                # 3. It does not perform cross-sensor consistency checks
                if (
                    no_filtering
                    or weak_filtering
                    or lacks_cross_sensor_consistency_checks
                ):
                    return True

        return False
