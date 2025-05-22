import os.path
from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling.device import Device
from saci.modeling.device.sensor import GPSReceiver
from saci.modeling.communication import (
    UnauthenticatedCommunication,
    ExternalInput,
    LossOfSignal,
)
from saci.modeling.attack_vector import (
    BaseAttackVector,
    BaseCompEffect,
    GPSAttackSignal,
)


# Predicate to define formal reasoning logic for GPS jamming vulnerabilities
class GPSJammingPred(Predicate):
    pass


class GPSJammingVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            # The GPSReceiver component vulnerable to jamming attacks
            component=GPSReceiver(),
            # Input: Unauthenticated noise/interference signals from external jammer
            _input=UnauthenticatedCommunication(src=ExternalInput),
            # Output: Loss of GPS signal resulting in failure to acquire valid positioning
            output=LossOfSignal(),
            # Halima: modeling discussion
            ###################
            # class LossOfSignal(BaseCommunication):
            #         def __init__(self, src=None, dst=None, reason="Jamming Interference", identifier=None, seq=0):
            #             super().__init__(src=src, dst=dst, data=None)
            #             self.identifier = identifier
            #             self.seq = seq
            #             self.reason = reason
            ####################
            # Predicate for reasoning about GPS jamming vulnerabilities
            attack_ASP=GPSJammingPred,
            # Logic rules for evaluating this vulnerability
            rulefile=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "gps_jamming.lp"
            ),
            # List of Associated CWEs relevant to GPS jamming:
            associated_cwe=[
                "CWE-400: Uncontrolled Resource Consumption",
                "CWE-703: Improper Check or Handling of Exceptional Conditions",
                "CWE-693: Protection Mechanism Failure",
                "CWE-755: Improper Handling of Exceptional Conditions",
            ],
            attack_vectors_exploits=[
                {
                    # Attack vectors related to GPS signal jamming:
                    "attack_vector": [
                        BaseAttackVector(
                            name="GPS Signal Jamming Attack",
                            signal=GPSAttackSignal(
                                src=ExternalInput(),
                                dst=GPSReceiver(),
                                modality="gps_signals",
                            ),
                            required_access_level="Proximity",
                            configuration={
                                "attack_type": "GPS Signal Jamming",
                                "signal_modality": "gps_signals",
                                "target_components": ["GPSReceiver"],
                                "required_access": "Proximity",
                            },
                        )
                    ],
                    # Associated CPVs relevant to GPS jamming scenarios:
                    "related_cpv": ["GPSJammingNoDriveCPV"],
                    # Associated component-level attack effects specifically for jamming:
                    "comp_attack_effect": [
                        BaseCompEffect(
                            category="Availability",
                            description="GPS signal jamming prevents the device from obtaining a valid GPS fix, rendering navigation and movement impossible.",
                        )
                    ],
                    # Steps specific to GPS jamming exploitation:
                    "exploit_steps": [
                        "Deploy SDR (e.g., HackRF) near target GPS device.",
                        "Configure SDR parameters (frequency, power) to effectively jam the GPS L1 frequency.",
                        "Begin transmission of GPS jamming signals.",
                        "Confirm loss of GPS fix on the target device.",
                        "Maintain jamming transmission to sustain denial of GPS service.",
                    ],
                    # Relevant references specifically about GPS jamming:
                    "reference_urls": [
                        "https://gpspatron.com/spoofing-a-multi-band-rtk-gnss-receiver-with-hackrf-one-and-gnss-jammer",
                        "https://github.com/Mictronics/multi-sdr-gps-sim",
                        "https://kaitlyn.guru/projects/spoofing-gps-with-an-sdr/",
                        "https://github.com/senpai-on-fire/ngc2_taskboard/blob/main/CPVs/HII-NGP1AROV2ARR05-CPV008/HII-NGP1AROV2ARR05-CPV008-20250501.docx",
                    ],
                }
            ],
        )

    def exists(self, device: Device) -> bool:
        # Check explicitly for GPSReceiver lacking anti-jamming protection
        for comp in device.components:
            if isinstance(comp, GPSReceiver):
                if not getattr(comp, "has_anti_jamming_protection", False):
                    return True  # Vulnerability detected
        return False  # No vulnerability detected if anti-jamming protection is present
