import os.path

from clorm import Predicate

from saci.modeling import PublicSecretVulnerability
from saci.modeling.device import Device, Wifi, SikRadio, Telemetry
from saci.modeling.communication import (
    BaseAttackVector,
    AuthenticatedCommunication,
    UnauthenticatedCommunication,
    ExternalInput,
)
from saci.modeling.attack import BaseCompEffect


# Predicate to define formal reasoning logic for RF interference vulnerabilities
class SikRadioRFBlockingPred(Predicate):
    pass


class SikRadioRFBlockingVuln(PublicSecretVulnerability):
    def __init__(self):
        super().__init__(
            # The vulnerable component is the Wi-Fi communication stack
            component=SikRadio(),
            # Input: Shielded chamber to block the RF link
            _input=None,
            # Output: Disrupted communication leading to loss of control and telemetry
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about RF interference vulnerabilities
            attack_ASP=SikRadioRFBlockingPred,
            # Optional rule file for logic-based reasoning about RF interference
            rulefile=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "sikradio_rf_blocking.lp"
            ),
            # List of Associated CWEs:
            associated_cwe=[
                "CWE-770: Allocation of Resources Without Limits or Throttling",
                "CWE-400: Uncontrolled Resource Consumption",
                "CWE-693: Protection Mechanism Failure",
                "CWE-661: Improper Handling of Overlapping or Conflicting Actions",
                "CWE-1188: Insecure Default Initialization of Resource",
            ],
            attack_vectors_exploits=[
                {
                    "attack_vector": [
                        BaseAttackVector(
                            name="RF Blocking Attack",
                            required_access_level="Physical",
                            configuration={
                                "attack_method": "RF blocking",
                                "target": "CPS communication channel",
                            },
                        )
                    ],
                    "related_cpv": ["RFBlockingCPV"],
                    "comp_attack_effect": [
                        BaseCompEffect(
                            category="Denial of Service",
                            description="Blocks telemetry and control signals",
                        )
                    ],
                    "exploit_steps": [
                        "Power on the CPS and remote controller",
                        "Place CPS in shielded chamber",
                        "Observe that all controls do not work",
                    ],
                    "reference_urls": [
                        "https://github.com/senpai-on-fire/owlet-taskboard/blob/main/CPVs/IVV_Feedback/PASS/HII-GS0409380007-CPV008-202503061.docx"
                    ],
                }
            ],
        )
        # Human-readable description of the attack input scenario
        self.input = "Deliberate RF blocking targeting the UAV's communication channel using a shielded chamber."

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a Wi-Fi stack. Note that RF interference protection would not be useful as all communication is blocked
            if isinstance(comp, SikRadio):
                return True  # Vulnerability exists if the component uses any kind of Radio channel
        return False  # No vulnerability detected if no Wi-Fi
