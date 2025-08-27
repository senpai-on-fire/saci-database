import os.path
from clorm import Predicate

from saci.modeling import PublicSecretVulnerability
from saci.modeling.device import Device, ArduinoGigaR1
from saci.modeling.communication import UnauthenticatedCommunication, ExternalInput
from saci.modeling.attack import BaseCompEffect
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.firmware_attack_signal import FirmwareAttackSignal


# Predicate to define formal reasoning logic for firmware overwrite attacks
class FirmwareOverwritePred(Predicate):
    pass


class FirmwareOverwriteVuln(PublicSecretVulnerability):
    def __init__(self):
        super().__init__(
            # The vulnerable component is the Arduino Giga R1 programmable memory
            component=ArduinoGigaR1(),
            # Input: Direct unauthenticated communication via USB-C firmware upload
            _input=UnauthenticatedCommunication(src=ExternalInput()),
            # Output: Compromised component state due to overwritten firmware
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about firmware overwrite attacks
            attack_ASP=FirmwareOverwritePred,
            # Logic rules for evaluating firmware overwrite vulnerabilities
            rulefile=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "firmware_overwrite.lp"
            ),
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
                    # Attack vector: Firmware Overwrite via Arduino IDE USB upload
                    "attack_vector": [
                        BaseAttackVector(
                            name="Firmware Overwrite via USB-C Interface",
                            signal=FirmwareAttackSignal(
                                src=ExternalInput(), dst=ArduinoGigaR1()
                            ),
                            required_access_level="Physical",
                            configuration={
                                "method": "Arduino IDE USB Upload",
                                "interface": "USB-C",
                            },
                        )
                    ],
                    # List of associated CPVs
                    "related_cpv": ["ArduinoGigaFirmwareOverwriteCPV"],
                    # List of associated component-level attack effects
                    "comp_attack_effect": BaseCompEffect(
                        category="Integrity",
                        description="Firmware overwrite leads to complete loss of component functionality, including Wi-Fi and motor control.",
                    ),
                    # Steps of exploiting this attack vector
                    "exploit_steps": [
                        "Power off rover.",
                        "Connect Arduino Giga R1 via USB-C to attacker computer.",
                        "Open Arduino IDE and select Arduino Giga R1.",
                        "Upload a blank sketch to Arduino Giga R1.",
                        "Disconnect Arduino Giga R1 and power on rover.",
                        "Verify rover functionality is compromised (no Wi-Fi, no motor control).",
                    ],
                    # List of related references
                    "reference_urls": [
                        "https://docs.arduino.cc/tutorials/giga-r1-wifi/giga-getting-started",
                        "https://cwe.mitre.org/data/definitions/494.html",
                        "https://cwe.mitre.org/data/definitions/347.html",
                    ],
                }
            ],
        )

    def exists(self, device: Device) -> bool:
        """
        Checks if the device is vulnerable to firmware overwrite attacks.
        The vulnerability exists if:
        - The device has programmable flash memory
        - The firmware update lacks proper authentication/verification
        """
        for comp in device.components:
            if isinstance(comp, ArduinoGigaR1) and comp.has_programmable_flash:
                return not device.has_firmware_verification
        return False
