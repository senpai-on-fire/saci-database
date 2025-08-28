import os.path

from clorm import Predicate

from saci.modeling import SpoofingVulnerability
from saci.modeling.device import Device
from saci.modeling.device.sensor.barometer import Barometer, BarometerHWPackage
from saci.modeling.communication import (
    AuthenticatedCommunication,
    ExternalInput,
)
from saci.modeling.attack import (
    BaseAttackVector,
    EnvironmentalInterference,
    BaseCompEffect,
)


# Predicate to define formal reasoning logic for barometer spoofing attacks
class BarometerSpoofingPred(Predicate):
    pass


class BarometerSpoofingVuln(SpoofingVulnerability):
    def __init__(self):
        super().__init__(
            # The barometer component vulnerable to spoofing attacks
            component=Barometer(),
            # Input: Spoofed signals injected via authenticated communication from an external source
            _input=AuthenticatedCommunication(src=ExternalInput()),
            # Output: authenticated communication representing the result of the spoofed barometer signals
            output=AuthenticatedCommunication(),
            # Predicate for formal reasoning about barometer spoofing
            attack_ASP=BarometerSpoofingPred,
            # Logic rules for reasoning about the barometer spoofing vulnerability
            rulefile=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "barometer_spoofing.lp"
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
                            name="Barometric Sensor Spoofing",
                            signal=EnvironmentalInterference(
                                src=ExternalInput(),
                                dst=Barometer(),
                            ),
                            required_access_level="Proximity",
                            configuration={
                                "attack_method": "Tampering with sensor output using audio signals",
                                "equipment": "Very loud speaker (100dB)",
                            },
                        )
                    ],
                    "related_cpv": ["BarometricSensorSpoofingCPV"],
                    "comp_attack_effect": [
                        BaseCompEffect(
                            category="Integrity",
                            description="Audio interference can cause unauthorized altitude perception and navigation errors through signal data tampering",
                        )
                    ],
                    "exploit_steps": [
                        "Determine the resonant frequency of the barometer sensor installed on the UAV.",
                        "Point the spoofing audio source device towards the UAV and play the sound noise.",
                        "Observe the UAV's erratic movements in response to spoofed sensor readings.",
                    ],
                    "reference_urls": [
                        "https://ieeexplore.ieee.org/document/8802817",
                        "https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=7961948",
                    ],
                }
            ],
        )

    def exists(self, device: Device) -> bool:
        # These are new But these are DIFFERENTIAL
        vuln_sensor_list = [
            "P1K-2-2X16PA",
            "MPVZ5004GW7U",
            "SDP810-250PA",
            "SDP810-500PA",
            "P993-1B",
            "A1011-00",
        ] + BarometerHWPackage.KNOWN_CHIP_NAMES
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a barometer,
            if isinstance(comp, Barometer):
                if hasattr(comp, "chip_name") and comp.chip_name in vuln_sensor_list:
                    return True  # This in the future could be 100%
                if hasattr(comp, "chip_type") and comp.chip_type == "MEMS":
                    if (
                        not hasattr(comp, "acoustic_isolation")
                        or not comp.acoustic_isolation
                    ):
                        return True  # If it doesn't have the acoustic isolation attribute, it is assumed it doesnt have it. If it has the attribute and specified as false, then it is vulnrable
        return False  # No vulnerability detected if no barometer is found, and it is not MEMS
