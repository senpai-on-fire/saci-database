import os.path
from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling.device import Device, PowerCable
from saci.modeling.communication import AuthenticatedCommunication
from saci.modeling.attack import BaseCompEffect, BaseAttackVector
from saci.modeling.attack.magnetic_attack_signal import MagneticAttackSignal


# Predicate to define formal reasoning logic for vulnerabilities caused by lack of EMI shielding on sensors
class LackEMIPowerCableShieldingPred(Predicate):
    pass


class LackEMIPowerCableShieldingVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            # The Sensor component is vulnerable due to lack of EMI shielding
            component=PowerCable(),
            # Input: None
            _input=None,
            # Output: EM radiation.
            output=AuthenticatedCommunication(),
            # Predicate for reasoning about EMI shielding vulnerabilities in sensors
            attack_ASP=LackEMIPowerCableShieldingPred,
            # Logic rules for evaluating this vulnerability in formal reasoning
            rulefile=os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                "lack_emi_powercable_shielding.lp",
            ),
            # List of Associated CWEs:
            associated_cwe=[
                "CWE-346: Origin Validation Error",
                "CWE-20: Improper Input Validation",
                "CWE-693: Protection Mechanism Failure",
                "CWE-1188: Insecure Default Initialization of Resource",
                "CWE-770: Allocation of Resources Without Limits or Throttling",
                "CWE-400: Uncontrolled Resource Consumption",
            ],
            attack_vectors=[
                {
                    "attack_vector": [
                        BaseAttackVector(
                            name="Electromagnetic Signals Interference",
                            signal=MagneticAttackSignal(src=PowerCable()),
                            required_access_level="Physical",
                            configuration={
                                "attack_method": "Move power cable near magnetometer to enhance potential EMI",
                                "duration": "permanent",
                            },
                        )
                    ],
                    "related_cpv": ["EMIPowerCableMagnetometerCPV"],
                    "comp_attack_effect": [
                        BaseCompEffect(
                            category="Manipulation of Control",
                            description="Cable can be a source of interference for CPS components or potentially get interferance from external soruces",
                        )
                    ],
                    "exploit_steps": [
                        "Power on the CPS",
                        "Locate power cables and try to measure current passing through them using a current clamp",
                        "If you get a current reading, this implies the wire cable has no shielding",
                        "If you can't get the current clamp around the wire: ",
                        "  place a magnetometer (preferably a 3 axis one) far from the cable to test and also away from any other wires",
                        "  Gradually move the magnetometer close to the cable while maintaining its orientation.",
                        "  Observe any variation in the readings",
                        "  Variation in readings indicate lack of EMI shielding",
                    ],
                    "reference_urls": [
                        "https://github.com/senpai-on-fire/ngc2_taskboard/blob/main/CPVs/HII-NGP1AROV2ARR05-CPV014/HII-NGP1AROV2ARR05-CPV014-20250513.docx",
                        "https://github.com/senpai-on-fire/ngc2_taskboard/blob/main/CPVs/HII-NGP1AROV2ARR05-CPV014/CPV_candidate_8.docx",
                    ],
                }
            ],
        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a Sensor and lacks proper EMI shielding
            if isinstance(comp, PowerCable):
                # Assuming there is an attribute 'has_emi_shielding' indicating if the sensor is shielded
                if not getattr(comp, "has_emi_shielding", False):  # Default to False if the attribute is missing
                    return True  # Vulnerability exists if the sensor lacks shielding
        return False  # No vulnerability detected if all sensors are properly shielded
