import os.path
from clorm import Predicate

from saci.modeling import PublicSecretVulnerability
from saci.modeling.device import (
    Device,
    Wifi,
    Telemetry,
    TelemetryHigh,
    Mavlink,
    ExpressLRSBackpack,
)
from saci.modeling.communication import UnauthenticatedCommunication, ExternalInput
from saci.modeling.attack import BaseCompEffect
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.packet_attack_signal import PacketAttackSignal


# Predicate to define formal reasoning logic for firmware overwrite attacks
class FirmwareOverwritePred(Predicate):
    pass


class ExpressLRSFirmwareOverwriteVuln(PublicSecretVulnerability):
    def __init__(self):
        super().__init__(
            # The vulnerable component is the network interface
            component=ExpressLRSBackpack(),
            # Input: Unauthenticated network communication
            _input=UnauthenticatedCommunication(src=ExternalInput()),
            # Output: Unauthenticated communication leading to firmware modification
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about firmware overwrite attacks
            attack_ASP=FirmwareOverwritePred,
            # Logic rules for evaluating firmware update vulnerabilities
            rulefile=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "firmware_overwrite.lp"
            ),
            # List of Associated CWEs
            associated_cwe=[
                "CWE-494: Download of Code Without Integrity Check",
                "CWE-306: Missing Authentication for Critical Function",
                "CWE-287: Improper Authentication",
                "CWE-345: Insufficient Verification of Data Authenticity",
                "CWE-347: Improper Verification of Cryptographic Signature",
            ],
            attack_vectors_exploits=[
                {
                    # Attack vector: Firmware Overwrite via Network Interface
                    "attack_vector": [
                        BaseAttackVector(
                            name="Firmware Overwrite via Network Interface",
                            signal=PacketAttackSignal(
                                src=ExternalInput(), dst=Telemetry()
                            ),
                            required_access_level="Remote",
                        )
                    ],
                    # List of associated CPVs
                    "related_cpv": ["RC3ParameterManipulation", "GCSFirmwareOverwrite"],
                    # List of associated component-level attack effects
                    "comp_attack_effect": BaseCompEffect(
                        category="Integrity",
                        description="Firmware modification leads to loss of system control and potential system failure.",
                    ),
                    # Steps of exploiting this attack vector
                    "exploit_steps": [
                        "Identify target device network interface",
                        "Connect to device network",
                        "Access firmware update interface",
                        "Upload modified firmware or manipulated firmware parameters",
                        "Verify firmware modification impact",
                    ],
                    # List of related references
                    "reference_urls": [
                        "https://cwe.mitre.org/data/definitions/494.html",
                        "https://cwe.mitre.org/data/definitions/347.html",
                    ],
                },
                {
                    "attack_vector": [
                        BaseAttackVector(
                            name="MavLink Packets Injection",
                            signal=PacketAttackSignal(
                                src=Mavlink(), dst=ExpressLRSBackpack()
                            ),
                            required_access_level="Proximity",
                            configuration={
                                "protocol": "UDP",
                                "port": "14555",
                                "command": "param set",
                            },
                        )
                    ],
                    "related_cpv": ["FlightParametersRewriteCPV"],
                    "comp_attack_effect": BaseCompEffect(
                        category="Integrity",
                        description="The manipulation of parameters disrupts calibration of the sensors and causes a change in the CPS movement dynamics.",
                    ),
                    "exploit_steps": [
                        "Connect to the CPS via the ExpressLRS Backpack module using the default password 'expresslrs'.",
                        "Gain write access to the MAVLink messages of the CPS through a utility like MAVProxy.",
                        "Issue a param set command with the format 'param set {param_name} {value}' (ex: param set INS_GYROFFS_X 10).",
                        "Observe and verify the effect on the flight dynamics after overwriting different parameters.",
                    ],
                    "reference_urls": [
                        "https://github.com/senpai-on-fire/owlet-taskboard/blob/main/CPVs/IVV_Feedback/PASS/HII-GS0409380007-CPV004-20250303.docx"
                    ],
                },
            ],
        )

    def exists(self, device: Device) -> bool:
        """
        Checks if the device is vulnerable to firmware overwrite attacks.
        The vulnerability exists if:
        - The device has network capability
        - The device has firmware update functionality
        - The firmware update lacks proper authentication/verification
        """
        has_wifi = False
        has_telemetry = False

        for comp in device.components:
            if isinstance(comp, Wifi):
                has_wifi = True
            elif isinstance(comp, Telemetry):
                has_telemetry = True

        # Device must have network interface and lack firmware verification
        return has_wifi and has_telemetry and not device.has_firmware_verification
