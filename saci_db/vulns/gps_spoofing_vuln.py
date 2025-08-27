import os.path

from clorm import Predicate

from saci.modeling import SpoofingVulnerability
from saci.modeling.attack import BaseCompEffect
from saci.modeling.device import Device
from saci.modeling.device.sensor import GPSReceiver
from saci.modeling.communication import (
    AuthenticatedCommunication,
    UnauthenticatedCommunication,
    ExternalInput,
)
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.gps_attack_signal import GPSAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact


# Predicate to define formal reasoning logic for GPS spoofing attacks
class GPSSpoofingPred(Predicate):
    pass


class GPSSpoofingVuln(SpoofingVulnerability):
    def __init__(self):
        super().__init__(
            # The GPSReceiver component vulnerable to spoofing attacks
            component=GPSReceiver(),
            # Input: Unauthenticated GPS signals spoofed by an external source
            _input=UnauthenticatedCommunication(src=ExternalInput),
            # Output: Unauthenticated communication leading to erroneous navigation decisions
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about GPS spoofing vulnerabilities
            attack_ASP=GPSSpoofingPred,
            # Logic rules for evaluating this vulnerability in formal reasoning
            rulefile=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "gps_spoofing.lp"
            ),
            # List of Associated CWEs:
            associated_cwe=[
                "CWE-290: Authentication Bypass by Capture-replay",
                "CWE-346: Origin Validation Error",
                "CWE-20: Improper Input Validation",
                "CWE-693: Protection Mechanism Failure",
                "CWE-1188: Insecure Default Initialization of Resource",
            ],
            attack_vectors=[
                {
                    # List of related attack vectors and their exploitation information:
                    "attack_vector": [
                        BaseAttackVector(
                            name="GPS Signal Spoofing Attack",
                            signal=GPSAttackSignal(
                                src=ExternalInput(),
                                dst=GPSReceiver(),
                                modality="gps_signals",
                            ),
                            required_access_level="Remote",
                            configuration={
                                "attack_type": "GPS Position Manipulation",
                                "signal_modality": "gps_signals",
                                "target_components": ["GPSReceiver"],
                                "required_access": "Remote",
                            },
                        )
                    ],
                    # List of associated CPVs
                    "related_cpv": [
                        "GPSSpoofingMoveCPV",
                        "GPSSpoofingStaticCPV",
                        "GPSSpoofingLoopCPV",
                        "PathManipulationCPV",
                        "DirectionalManipulationCPV",
                        "FailSafeAvoidanceCPV",
                    ],
                    # List of associated component-level attack effects
                    "comp_attack_effect": [
                        BaseCompEffect(
                            category="Integrity",
                            # TODO: how to tell what integrity violation is more severe?
                            # TODO: What are the exepcted changes in the component output/behavior?
                            description="GPS signal manipulation can cause unauthorized device movement, navigation deviation, and safety mechanism bypass through signal data tampering",
                        )
                    ],
                    # Steps of exploiting this attack vector
                    "exploit_steps": [
                        "Deploy GPS spoofing equipment near target device",
                        "Configure spoofing parameters based on target device",
                        "Inject modified GPS signals with desired coordinates",
                        "Monitor device response and adjust spoofing parameters",
                        "Maintain spoofing while avoiding safety triggers",
                        "Guide device to desired location or behavior",
                    ],
                    # List of related references
                    "reference_urls": [
                        "https://www.usenix.org/conference/usenixsecurity22/presentation/zhou-ce",
                        "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV007",
                        "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV013",
                        "https://dl.acm.org/doi/10.1145/3309735",
                    ],
                }
            ],
        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a GPSReceiver
            if isinstance(comp, GPSReceiver):
                # Verify if the GPSReceiver supports unauthenticated protocols
                if hasattr(comp, "supported_protocols"):
                    supported_protocols = comp.supported_protocols
                    for protocol in supported_protocols:
                        # If the protocol is unauthenticated, the vulnerability exists
                        if issubclass(protocol, UnauthenticatedCommunication):
                            return True  # Vulnerability detected
        return False  # No vulnerability detected if no matching conditions are met
