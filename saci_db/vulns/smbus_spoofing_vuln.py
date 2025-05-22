import os.path
from clorm import Predicate

from saci.modeling import SpoofingVulnerability
from saci.modeling.device import Device, SMBus
from saci.modeling.communication import (
    AuthenticatedCommunication,
    UnauthenticatedCommunication,
    ExternalInput,
)
from saci.modeling.attack import BaseAttackVector, SerialAttackSignal
from saci.modeling.attack import BaseCompEffect


# Predicate to define formal reasoning logic for SMBus vulnerabilities
class SMBusVulnPred(Predicate):
    pass


class SMBusVuln(SpoofingVulnerability):
    def __init__(self):
        super().__init__(
            # The SMBus component vulnerable to spoofing attacks
            component=SMBus(),
            # Input: Unauthenticated communication representing spoofed signals from an external source
            _input=UnauthenticatedCommunication(src=ExternalInput()),
            # Output: Unauthenticated communication leading to erroneous system behavior
            output=UnauthenticatedCommunication(),
            # Predicate for formal reasoning about SMBus vulnerabilities
            attack_ASP=SMBusVulnPred,
            # Logic rules for evaluating this vulnerability in formal reasoning
            rulefile=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "smbus_vuln.lp"
            ),
            # List of Associated CWEs:
            associated_cwe=[
                "CWE-346: Origin Validation Error",
                "CWE-20: Improper Input Validation",
                "CWE-693: Protection Mechanism Failure",
            ],
            attack_vectors_exploits=[
                {
                    "attack_vector": [
                        BaseAttackVector(
                            name="SMBus Command Injection",
                            signal=SerialAttackSignal(
                                src=ExternalInput(),
                                dst=SMBus(),
                            ),
                            required_access_level="Physical",
                            configuration={
                                "equipment": "TI EV2400 EVM Interface board",
                            },
                        )
                    ],
                    "related_cpv": ["SMBusBatteryShutdownCPV"],
                    "comp_attack_effect": [
                        BaseCompEffect(
                            category="Availability",
                            description="Command injection can cause the system to shut down, leading to loss of power and control.",
                        )
                    ],
                    "exploit_steps": [
                        "Connect an SMBus cable between the SMBus connector on the EV2400 and J3 on the battery monitor board.",
                        "Power system on using only battery power.",
                        "Open BQStudio and connect to the BQ40Z80 device.",
                        "Inject the shutdown command via BQStudio to disable the system.",
                    ],
                    "reference_urls": [
                        "https://github.com/senpai-on-fire/Greensight1A-esc-CPVs/blob/main/CPV001/HII-GSP1AESC01NR017-CPV001-20240926.docx"
                    ],
                }
            ],
        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is an SMBus
            if isinstance(comp, SMBus):
                return True  # Vulnerability exists if an SMBus is found
        return False  # No vulnerability detected if no SMBus is found
