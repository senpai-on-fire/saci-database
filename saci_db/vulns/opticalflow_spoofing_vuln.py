import os.path
from clorm import Predicate
from saci.modeling import SpoofingVulnerability
from saci.modeling.device import Device
from saci.modeling.device.sensor import OpticalFlowSensor
from saci.modeling.communication import (
    AuthenticatedCommunication,
    UnauthenticatedCommunication,
    ExternalInput,
)
from saci.modeling.attack import BaseAttackVector, ImageAttackSignal, BaseCompEffect


# Predicate to define formal reasoning logic for optical flow spoofing attacks
class OpticalFlowSpoofingPred(Predicate):
    pass


class OpticalFlowSpoofingVuln(SpoofingVulnerability):
    def __init__(self):
        super().__init__(
            # The OpticalFlowSensor component vulnerable to spoofing attacks
            component=OpticalFlowSensor(),
            # Input: Authenticated communication representing spoofed optical flow data
            _input=AuthenticatedCommunication(),
            # Output: Authenticated communication leading to erroneous motion detection or navigation decisions
            output=AuthenticatedCommunication(),
            # Predicate for reasoning about optical flow spoofing vulnerabilities
            attack_ASP=OpticalFlowSpoofingPred,
            # Logic rules for evaluating optical flow spoofing vulnerabilities in formal reasoning
            rulefile=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "optical_flow_spoofing.lp"
            ),
            # List of Associated CWEs:
            associated_cwe=[
                "CWE-346: Origin Validation Error",
                "CWE-290: Authentication Bypass by Capture-replay",
                "CWE-20: Improper Input Validation",
                "CWE-693: Protection Mechanism Failure",
                "CWE-1188: Insecure Default Initialization of Resource",
            ],
            attack_vectors=[
                {
                    "attack_vector": [
                        BaseAttackVector(
                            name="Optical Flow Spoofing Signal Injection",
                            signal=ImageAttackSignal(
                                src=ExternalInput(),
                                dst=OpticalFlowSensor(),
                                modality="image",
                            ),
                            required_access_level="Physical",
                            configuration={
                                "attack_type": "Optical Flow Manipulation",
                                "signal_modality": "image",
                                "target_components": ["OpticalFlowSensor"],
                                "required_access": "Physical",
                            },
                        )
                    ],
                    "related_cpv": ["ProjectorOpticalFlowCPV"],
                    "comp_attack_effect": [
                        BaseCompEffect(
                            category="Integrity",
                            description="Optical flow signal manipulation can cause unauthorized device movement and navigation deviation through image data tampering",
                        )
                    ],
                    "exploit_steps": [
                        "Position the spoofing device in the UAV's optical flow sensor field.",
                        "Project high-contrast patterns using a laser or projector.",
                        "Move the projected pattern to mislead corner detection algorithms.",
                        "Observe the drone drift following the displacement of the projected pattern.",
                    ],
                    "reference_urls": [
                        "https://www.usenix.org/system/files/conference/woot16/woot16-paper-davidson.pdf"
                    ],
                }
            ],
        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is an OpticalFlowSensor
            if isinstance(comp, OpticalFlowSensor):
                # Ensure the sensor uses corner detection and is enabled
                if comp.uses_corner_detection() and comp.enabled():
                    return True  # Vulnerability exists if the conditions are met
        return False  # No vulnerability detected if no matching sensor is found
