import os.path

from clorm import Predicate

from saci.modeling import SpoofingVulnerability 

from saci.modeling.device import Device
from saci.modeling.device.sensor import Barometer

from saci.modeling.communication import AuthenticatedCommunication, ExternalInput
from saci.modeling.attack import BaseAttackVector, BaseCompEffect


class BarometerObstructionPred(Predicate):
    """Placeholder predicate for logic reasoning about barometer obstruction."""

    pass


class BarometerObstructionVuln(SpoofingVulnerability):
    """Vulnerability model: Physical blockage of the barometer static‑pressure port
    resulting in corrupted altitude readings.
    """

    def __init__(self):
        super().__init__(
            component=Barometer(),
            _input=AuthenticatedCommunication(src=ExternalInput()),  # physical access proxy
            output=AuthenticatedCommunication(),
            attack_ASP=BarometerObstructionPred,
            # No dedicated rule file yet
            associated_cwe=[
                "CWE-346: Origin Validation Error",
                "CWE-20: Improper Input Validation",
                "CWE-693: Protection Mechanism Failure",
            ],
            attack_vectors_exploits=[
                {
                    "attack_vector": [
                        BaseAttackVector(
                            name="Static‑Port Blockage",
                            signal=None,
                            required_access_level="close physical",
                            configuration={
                                "tool": "tape / putty / dust",
                                "duration": "until removal",
                            },
                        )
                    ],
                    "related_cpv": [
                        "BarometerBlockingCPV",
                    ],
                    "comp_attack_effect": [
                        BaseCompEffect(
                            category="Integrity",
                            description="Sensor stuck at constant pressure -> false altitude estimate -> throttle instability",
                        )
                    ],
                    "exploit_steps": [
                        "Locate barometer driver; verify no sanity checks on constant pressure values.",
                        "In SITL, freeze baro reading; observe altitude PID wind‑up.",
                        "Cover static port; log altitude estimate & throttle, then uncover to confirm recovery.",
                    ],
                    "reference_urls": [
                        # No specific academic publications (as of 2025‑05‑21)
                    ],
                }
            ],
        )

    def exists(self, device: Device) -> bool:  

        for comp in device.components.values():
            if isinstance(comp, Barometer):
                return True
        return False
