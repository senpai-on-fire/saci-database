import os.path

from clorm import Predicate

from saci.modeling import SpoofingVulnerability
from saci.modeling.device import Device
from saci.modeling.device.sensor import Magnetometer
from saci.modeling.communication import (
    AuthenticatedCommunication,
    UnauthenticatedCommunication,
    ExternalInput,
)
from saci.modeling.attack import (
    BaseAttackVector,
    MagneticAttackSignal,
    AcousticAttackSignal,
    BaseCompEffect,
)


# Predicate to define formal reasoning logic for magnetometer spoofing attacks
class MagnetometerSpoofingPred(Predicate):
    pass


class MagnetometerSpoofingVuln(SpoofingVulnerability):
    def __init__(self):
        super().__init__(
            # The Magnetometer component vulnerable to spoofing attacks
            component=Magnetometer(),
            # Input: Authenticated communication representing spoofed magnetometer signals from an external source
            _input=AuthenticatedCommunication(src=ExternalInput()),
            # Output: Authenticated communication leading to erroneous navigation decisions based on spoofed data
            output=AuthenticatedCommunication(),
            # Predicate for reasoning about magnetometer spoofing vulnerabilities
            attack_ASP=MagnetometerSpoofingPred,
            # Logic rules for evaluating magnetometer spoofing vulnerabilities in formal reasoning
            rulefile=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "magnetometer_spoofing.lp"
            ),
            # List of Associated CWEs:
            associated_cwe=[
                "CWE-346: Origin Validation Error",
                "CWE-290: Authentication Bypass by Capture-replay",
                "CWE-20: Improper Input Validation",
                "CWE-693: Protection Mechanism Failure",
                "CWE-1188: Insecure Default Initialization of Resource",
            ],
            attack_vectors_exploits=[
                {
                    "attack_vector": [
                        BaseAttackVector(
                            name="Electromagnetic Signal Interference",
                            signal=MagneticAttackSignal(
                                src=ExternalInput(),
                                dst=Magnetometer(),
                            ),
                            required_access_level="Proximity",
                            configuration={
                                "attack_method": "Emit electromagnetic interference targeting the magnetometer sensor or its communication channel",
                                "equipment": "High-power EMI emitter",
                                "target_frequency": "Specific to the magnetometer sensor's sensitivity range or the controller used",
                            },
                        )
                    ],
                    "related_cpv": [
                        "EMISpoofingMagnetometerCPV",
                        "MagnetometerEMIChannelDisruptionCPV",
                    ],
                    "comp_attack_effect": [
                        BaseCompEffect(
                            category="Integrity",
                            description="Electromagnetic interference can cause unauthorized device movement and navigation errors through signal data tampering",
                        )
                    ],
                    "exploit_steps": [
                        "Identify the operating characteristics and sensitivity range of the UAV's magnetometer sensor.",
                        "Acquire or construct a high-power EMI emitter capable of generating interference within the identified sensitivity range.",
                        "Position the EMI emitter in proximity to the UAV, ensuring line-of-sight to the magnetometer sensor or its communication channel.",
                        "Activate the EMI emitter to introduce interference, corrupting the magnetometer sensor's readings or its communication.",
                        "Monitor the UAV's behavior for signs of orientation miscalculation or navigation errors.",
                    ],
                    "reference_urls": [
                        "https://ieeexplore.ieee.org/document/9245834",
                        "https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_f616_paper.pdf",
                    ],
                },
                {
                    "attack_vector": [
                        BaseAttackVector(
                            name="Acoustic Signal Interference",
                            signal=AcousticAttackSignal(
                                src=ExternalInput(),
                                dst=Magnetometer(),
                                modality="audio",
                            ),
                            required_access_level="Physical",
                            configuration={
                                "attack_method": "Emit acoustic interference targeting the magnetometer sensor",
                                "equipment": "Speaker or Ultrasonic Sound Source",
                                "target_frequency": "Resonant frequency of the magnetometer sensor",
                            },
                        )
                    ],
                    "related_cpv": ["AcousticSpoofingMagnetometerCPV"],
                    "comp_attack_effect": [
                        BaseCompEffect(
                            category="Integrity",
                            description="Acoustic interference can cause unauthorized device movement and navigation errors through signal data tampering",
                        )
                    ],
                    "exploit_steps": [
                        "Determine the resonant frequency of the magnetometer sensor installed on the CPS.",
                        "Point the spoofing audio source device towards the CPS and play the sound noise.",
                        "Observe the CPS's erratic movements in response to spoofed sensor readings.",
                    ],
                    "reference_urls": [
                        "https://www.blackhat.com/docs/us-17/thursday/us-17-Wang-Sonic-Gun-To-Smart-Devices-Your-Devices-Lose-Control-Under-Ultrasound-Or-Sound.pdf"
                    ],
                },
            ],
        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a Magnetometer
            if isinstance(comp, Magnetometer):
                return True  # Vulnerability exists if a magnetometer is found
        return False  # No vulnerability detected if no magnetometer is found
