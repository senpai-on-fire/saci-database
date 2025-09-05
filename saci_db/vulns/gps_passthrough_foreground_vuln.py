import os.path
from clorm import Predicate

from saci.modeling.vulnerability import PublicSecretVulnerability
from saci.modeling.device import Device, Passthrough
from saci.modeling.communication import UnauthenticatedCommunication, ExternalInput
from saci.modeling.attack import BaseCompEffect
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.packet_attack_signal import SerialAttackSignal


# Predicate to define formal reasoning logic for firmware overwrite attacks
class GPSPassthroughForegroundPred(Predicate):
    pass


class GPSPassthroughForegroundVuln(PublicSecretVulnerability):
    def __init__(self):
        super().__init__(
            # The vulnerable component is the Arduino Giga R1 programmable memory
            component=Passthrough(),
            # Input: Direct unauthenticated communication via USB-C firmware upload
            _input=None,
            # Output: Unauthenticated termination of process
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about firmware overwrite attacks
            attack_ASP=GPSPassthroughForegroundPred,
            # Logic rules for evaluating firmware overwrite vulnerabilities
            rulefile=os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                "gps_passthrough_foreground.lp",
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
                    # Attack vector:
                    "attack_vector": [
                        BaseAttackVector(
                            name="Terminate Passthrough Process",
                            signal=SerialAttackSignal(src=ExternalInput(), dst=Passthrough()),
                            required_access_level="Physical",
                            configuration={"duration": "temporary"},
                        )
                    ],
                    # List of associated CPVs
                    "related_cpv": ["GPSPassthroughStopCPV"],
                    # List of associated component-level attack effects
                    "comp_attack_effect": BaseCompEffect(
                        category="Denial of Service",
                        description="The gps passthrough process is terminated thus the Controller never updates its location",
                    ),
                    # Steps of exploiting this attack vector
                    "exploit_steps": [
                        "Connect a USB-C cable to the microcontroller but do not plug the other end into a computer. This will prematurely power the microcontroller."
                        "Plug the serial connector of the serial adapter into the serial connector on the passthrough board. Plug the USB connector of the serial adapter into the computer. As serial doesn’t provide power this will not power the passthrough board.",
                        "Position the USB connector of the cable connected to the microcontroller near the computer so it can be plugged in quickly.",
                        "Open up one terminal emulator for the serial device exposed by the microcontroller.",
                        "Open up another terminal emulator for the serial device exposed by the serial adapter.",
                        "Turn on the CPS",
                        "Quickly plug in the USB cable connected to the microcontroller into the computer.",
                        "On the terminal emulator you will see the embedded Linux system boot sequence. This should continue until you see a bootup message and then output will stop.",
                        "Simultaneously, on the terminal emulator connected to the microcontroller you should see messages about the system booting up. Wait until you see a message indicating that a GPS lock is acquired",
                        "In the terminal emulator connected to the serial adapter enter “Ctrl-C” to terminate the passthrough process",
                        "Move the CPS 1 meter distance and observe if the location measured by the controller changes or not. No change indicates that the system is vulnerable",
                    ],
                    # List of related references
                    "reference_urls": [
                        "https://github.com/senpai-on-fire/ngc2_taskboard/blob/main/CPVs/HII-NGP1AROV2ARR05-CPV007/HII-NGP1AROV2ARR05-CPV007-20250425.docx"
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
            if isinstance(comp, Passthrough):
                return True
        return False
