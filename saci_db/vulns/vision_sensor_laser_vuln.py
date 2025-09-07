import os.path
from clorm import Predicate
from saci.modeling.vulnerability import SpoofingVulnerability
from saci.modeling.device import Device, Camera
from saci.modeling.communication import (
    UnauthenticatedCommunication,
    ExternalInput,
)
from saci.modeling.attack import BaseAttackVector, OpticalAttackSignal, BaseCompEffect


# Predicate to define formal reasoning logic for vision sensor laser attacks
class VisionSensorLaserPred(Predicate):
    pass


class VisionSensorLaserVuln(SpoofingVulnerability):
    def __init__(self):
        super().__init__(
            # The Camera component vulnerable to laser attacks
            component=Camera(),
            # Input: External laser interference
            _input=ExternalInput(),
            # Output: Disrupted vision perception
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about vision sensor laser vulnerabilities
            attack_ASP=VisionSensorLaserPred,
            # Logic rules for evaluating vision sensor laser vulnerabilities in formal reasoning
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), "vision_sensor_laser.lp"),
            # List of Associated CWEs:
            associated_cwe=[
                "CWE-20: Improper Input Validation",
                "CWE-693: Protection Mechanism Failure",
                "CWE-1188: Insecure Default Initialization of Resource",
            ],
            attack_vectors=[
                {
                    "name": "Laser Interference Attack",
                    "description": "Using laser pointer to disrupt camera vision sensor",
                    "attacks": [
                        BaseAttackVector(
                            impact=BaseCompEffect(
                                primary="Camera",
                                secondary="Controller",
                                effect="Disrupted vision perception leading to navigation errors",
                            ),
                            signal=OpticalAttackSignal(
                                src=ExternalInput(),
                                dst=Camera(),
                                data="660nm laser ~10000 lux"
                            ),
                        )
                    ],
                }
            ],
        )
