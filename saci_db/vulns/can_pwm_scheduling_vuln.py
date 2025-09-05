import os.path
from clorm import Predicate

from saci.modeling.vulnerability import PublicSecretVulnerability
from saci.modeling.device import Device, Controller
from saci.modeling.communication import (
    AuthenticatedCommunication,
    ExternalInput,
)
from saci.modeling.attack import BaseCompEffect
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.packet_attack_signal import (
    SerialAttackSignal,
)


# Predicate to define formal reasoning logic for firmware overwrite attacks
class CANPWMSchedulingPred(Predicate):
    pass


class CANPWMSchedulingVuln(PublicSecretVulnerability):
    def __init__(self):
        super().__init__(
            # The vulnerable component is the Arduino Giga R1 programmable memory
            component=Controller(),
            # Input: Direct authenticated communication, overload of CAN messages
            _input=AuthenticatedCommunication(),
            # Output: Delayed or dropped PWM signals
            output=AuthenticatedCommunication(),
            # Predicate for reasoning about firmware overwrite attacks
            attack_ASP=CANPWMSchedulingPred,
            # Logic rules for evaluating firmware overwrite vulnerabilities
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), "can_pwm_scheduling.lp"),
            # List of Associated CWEs relevant to firmware overwrite attacks
            associated_cwe=[
                "CWE-494: Download of Code Without Integrity Check",
                "CWE-306: Missing Authentication for Critical Function",
                "CWE-287: Improper Authentication",
                "CWE-345: Insufficient Verification of Data Authenticity",
                "CWE-347: Improper Verification of Cryptographic Signature",
            ],
            attack_vectors=[
                {
                    # Attack vector:
                    "attack_vector": [
                        BaseAttackVector(
                            name="Some form of input to increase the CAN message frequency",
                            signal=SerialAttackSignal(src=ExternalInput(), dst=Controller()),
                            required_access_level="Unknown",
                        )
                    ],
                    # List of associated CPVs
                    "related_cpv": ["CANMessagesDelayCPV"],
                    # List of associated component-level attack effects
                    "comp_attack_effect": BaseCompEffect(
                        category="Denial of Service",
                        description="The PWM signals are considerably delayed or no longer generated",
                    ),
                    # Steps of exploiting this attack vector
                    "exploit_steps": [
                        "There are currently no tested and proven steps to exploitation. A hypothesis is described below",
                        "Increase CAN message frequency coming from the controller",
                        "To simulate the effect of this denial of service, you can disconnect the signal pin from the ESC (pin 10 on the Uno) while the CPS is in operation.",
                    ],
                    # List of related references
                    "reference_urls": [
                        "https://github.com/senpai-on-fire/ngc2_taskboard/blob/main/CPVs/HII-NGP1AROV2ARR05-CPV016/HII-NGP1AROV2ARR05-CPV016-20250514.docx"
                    ],
                }
            ],
        )

    def exists(self, device: Device) -> bool:
        """
        Checks if the device is vulnerable to firmware overwrite attacks.
        The vulnerability exists if:
        """
        # Poor implementation :<
        for comp in device.components:
            if isinstance(comp, Controller):
                return True
        return False
