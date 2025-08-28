import os.path

from clorm import Predicate

from saci.modeling import SpoofingVulnerability
from saci.modeling.device import PWMChannel, Device
from saci.modeling.communication import (
    AuthenticatedCommunication,
    ExternalInput,
)
from saci.modeling.attack import BaseAttackVector, MagneticAttackSignal, BaseCompEffect


# Predicate to define formal reasoning logic for PWM spoofing attacks
class PWMSpoofingPred(Predicate):
    pass


class PWMSpoofingVuln(SpoofingVulnerability):
    def __init__(self):
        super().__init__(
            # The PWMChannel component is vulnerable to spoofing attacks
            component=PWMChannel(),
            # Input: Authenticated communication representing spoofed PWM signals from an external source
            _input=AuthenticatedCommunication(src=ExternalInput()),
            # Output: Authenticated communication resulting in erroneous commands sent to the ESC (Electronic Speed Controller)
            output=AuthenticatedCommunication(),
            # Predicate for reasoning about PWM spoofing vulnerabilities
            attack_ASP=PWMSpoofingPred,
            # Logic rules for evaluating PWM spoofing vulnerabilities in formal reasoning
            rulefile=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "pwm_spoofing.lp"
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
                            name="Electromagnetic Signals Interference",
                            signal=MagneticAttackSignal(
                                src=ExternalInput(), dst=PWMChannel()
                            ),
                            required_access_level="Remote",
                            configuration={"duration": "permanent"},
                        )
                    ],
                    "related_cpv": [
                        "EMIMotorBlockCPV",
                        "EMIMotorFullControlCPV",
                        "EMIMotorBlockRotateCPV",
                    ],
                    "comp_attack_effect": [
                        BaseCompEffect(
                            category="Availability",
                            description="Attacker can set motor RPM to a semi-constant value of 0 with some random spurious bursts",
                        )
                    ],
                    "exploit_steps": [
                        "Develop a Simulation Model: Create a comprehensive simulation model to analyze the impact of electromagnetic interference (EMI) on PWM-controlled actuators. Include controller logic, PWM signal generation, and EMI injection models.",
                        "Identify Key Parameters: Determine the PWM signal characteristics such as frequency and amplitude. Identify the resonant frequency of the PWM circuitry to enhance attack effectiveness. Establish the power level required for the interfering signal to disrupt motor operation.",
                        "Simulate Attack Effects: Simulate the effects of continuous wave (CW) signals interfering with legitimate PWM control signals. Observe system behavior under varying interference power levels and determine the minimum power required to block the PWM signal.",
                        "Evaluate and Validate: Evaluate the effectiveness of the attack and identify potential mitigation strategies, such as signal filtering or shielding. Validate findings by cross-referencing with theoretical models and prior research.",
                    ],
                    "reference_urls": [
                        "https://www.usenix.org/system/files/sec22-dayanikli.pdf"
                    ],
                }
            ],
        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a PWMChannel
            if isinstance(comp, PWMChannel):
                return True  # Vulnerability exists if a PWMChannel is found
        return False  # No vulnerability detected if no PWMChannel is found
