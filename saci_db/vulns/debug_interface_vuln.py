import os.path

from clorm import Predicate

from saci.modeling import SpoofingVulnerability
from saci.modeling.attack import BaseCompEffect
from saci.modeling.device import Device
from saci.modeling.device import Debug
from saci.modeling.communication import (
    UnauthenticatedCommunication,
    ExternalInput,
)
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.serial_attack_signal import SerialAttackSignal


# Predicate to define formal reasoning logic for Debug interface attacks
class DebugInterfacePred(Predicate):
    pass


class DebugInterfaceVuln(SpoofingVulnerability):
    def __init__(self):
        super().__init__(
            # The Debug component vulnerable to unauthorized access
            component=Debug(),
            # Input: Unauthenticated commands injected by an external source
            _input=UnauthenticatedCommunication(src=ExternalInput),
            # Output: Unauthenticated communication leading to unauthorized control
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about Debug interface vulnerabilities
            attack_ASP=DebugInterfacePred,
            # Logic rules for evaluating this vulnerability in formal reasoning
            rulefile=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "debug_interface.lp"
            ),
            # List of Associated CWEs:
            associated_cwe=[
                "CWE-287: Improper Authentication",
                "CWE-306: Missing Authentication for Critical Function",
                "CWE-20: Improper Input Validation",
                "CWE-693: Protection Mechanism Failure",
            ],
            attack_vectors=[
                {
                    # List of related attack vectors and their exploitation information:
                    "attack_vector": [
                        BaseAttackVector(
                            name="Debug Command Injection Attack",
                            signal=SerialAttackSignal(
                                src=ExternalInput(),
                                dst=Debug(),
                                data="specific sequence of bytes",
                            ),
                            required_access_level="Physical",
                            configuration={
                                "attack_type": "Command Injection",
                                "target_components": ["Debug"],
                            },
                        )
                    ],
                    # List of associated CPVs
                    "related_cpv": ["DebugESCFlashCPV"],
                    # List of associated component-level attack effects
                    "comp_attack_effect": [
                        BaseCompEffect(
                            category="Integrity",
                            description="Unauthorized command injection can cause system instability, unauthorized firmware changes, and potential device malfunction",
                        )
                    ],
                    # Steps of exploiting this attack vector
                    "exploit_steps": [
                        "Connect to the Debug interface using a USB-TTL serial adapter",
                        "Send specific command sequences to enter bootloader mode",
                        "Inject unauthorized commands to alter firmware or system settings",
                        "Monitor system response and adjust commands as needed",
                        "Ensure persistent access by modifying authentication settings",
                    ],
                    # List of related references
                    "reference_urls": [
                        "https://github.com/senpai-on-fire/Greensight1A-esc-CPVs/blob/main/CPV002/HII-GSP1AESC01NR017-CPV002-20240930.docx"
                    ],
                }
            ],
        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a Debug interface
            if isinstance(comp, Debug):
                # Verify if the Debug interface supports unauthenticated access
                if (
                    hasattr(comp, "supports_unauthenticated_access")
                    and comp.supports_unauthenticated_access
                ):
                    return True  # Vulnerability detected
        return False  # No vulnerability detected if no matching conditions are met
