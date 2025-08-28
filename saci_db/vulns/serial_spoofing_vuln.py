import os.path
from clorm import Predicate

from saci.modeling import SpoofingVulnerability
from saci.modeling.attack import BaseCompEffect
from saci.modeling.device import Device, Serial
from saci.modeling.communication import (
    UnauthenticatedCommunication,
    ExternalInput,
)
from saci.modeling.communication.protocol import UARTProtocol, I2CProtocol, SPIProtocol
from saci.modeling.attack.serial_attack_signal import SerialAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector


# Predicate to define formal reasoning logic for serial spoofing attacks
class SerialSpoofingPred(Predicate):
    pass


class SerialSpoofingVuln(SpoofingVulnerability):
    def __init__(self):
        super().__init__(
            # The Serial component is vulnerable to spoofing attacks
            component=Serial(),
            # Input: Unauthenticated communication used to spoof serial data
            _input=UnauthenticatedCommunication(),
            # Output: Unauthenticated communication representing manipulated or spoofed serial data
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about serial spoofing vulnerabilities
            attack_ASP=SerialSpoofingPred,
            # Logic rules for evaluating serial spoofing vulnerabilities in formal reasoning
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), "serial_spoofing.lp"),
            # List of Associated CWEs:
            associated_cwe=[
                "CWE-287: Improper Authentication",
                "CWE-294: Authentication Bypass by Capture-replay",
                "CWE-306: Missing Authentication for Critical Function",
                "CWE-345: Insufficient Verification of Data Authenticity",
                "CWE-20: Improper Input Validation",
                "CWE-1188: Insecure Default Initialization of Resource",
            ],
            attack_vectors=[
                {  # List of related attack vectors and their exploitation information:
                    "attack_vector": [
                        BaseAttackVector(
                            name="Serial DSHOT and Arduino Command Injection",
                            signal=SerialAttackSignal(src=ExternalInput(), dst=Serial(), data="any"),
                            required_access_level="Physical",
                            configuration={"command_types": ["DSHOT", "Arduino", "Settings"]},
                        )
                    ],
                    # List of associated CPVs
                    "related_cpv": [
                        "SerialRollOverCPV",
                        "SerialRedirectCPV",
                        "SerialToneCPV",
                        "SerialThrottleCPV",
                        "SerialArduinoControlCPV",
                    ],
                    # List of associated component-level attack effects
                    "comp_attack_effect": [
                        BaseCompEffect(
                            category="Integrity",
                            description="Serial command injection can cause unauthorized device movement, excessive speed, and potential rollover",
                        )
                    ],
                    # Steps of exploiting this attack vector
                    "exploit_steps": [
                        "Connect to device via serial interface",
                        "Send specific commands (e.g., DSHOT commands) repeatedly in idle state",
                        "Observe changes in device behavior",
                    ],
                    # List of related references
                    "reference_urls": [
                        "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV006",
                        "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV0011",
                        "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV014",
                    ],
                },
                {
                    "attack_vector": [
                        BaseAttackVector(
                            name="Serial ESC Command Injection",
                            signal=SerialAttackSignal(src=ExternalInput(), dst=Serial()),
                            required_access_level="Physical",
                        )
                    ],
                    # List of associated CPVs
                    "related_cpv": [
                        "SerialESCBootloaderCPV",
                        "SerialESCResetCPV",
                        "SerialESCDischargeCPV",
                        "SerialESCOverflowCPV",
                        "SerialESCExeccmdCPV",
                        "SerialOverheatingCPV",
                    ],
                    # List of associated component-level attack effects
                    "comp_attack_effect": [
                        BaseCompEffect(
                            category="Integrity",
                            description="Serial ESC command injection can cause motor failure, battery discharge issues, and potential hardware damage through overheating or buffer overflow",
                        )
                    ],
                    # Steps of exploiting this attack vector
                    "exploit_steps": [
                        "Connect to ESC via USB-TTL serial adapter",
                        "Send configuration modification commands",
                        "Observe abnormal device behavior",
                    ],
                    # List of related references
                    "reference_urls": [
                        "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV008",
                        "https://github.com/neoxic/ESCape32/wiki/Configuration#cli-command-line-interface",
                        "https://github.com/senpai-on-fire/Greensight1A-esc-CPVs/blob/main/CPV003/HII-GSP1AESC01NR017-CPV003-20241002.docx",
                        "https://github.com/senpai-on-fire/Greensight1A-esc-CPVs/blob/main/CPV004/HII-GSP1AESC01NR017-CPV004-20241003.docx",
                        "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV005",
                        "https://github.com/neoxic/ESCape32/wiki/Configuration#cli-command-line-interface",
                        "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV006",
                        "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV007",
                    ],
                },
            ],
        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component supports serial communication protocols
            if hasattr(comp, "supported_protocols"):
                supported_protocols = comp.supported_protocols
                # Iterate through the supported protocols
                for protocol in supported_protocols:
                    # Check if the protocol is UART, I2C, or SPI
                    if (
                        isinstance(protocol, UARTProtocol)
                        or isinstance(protocol, I2CProtocol)
                        or isinstance(protocol, SPIProtocol)
                    ):
                        return True  # Vulnerability exists if a supported protocol is found
        return False  # No vulnerability detected if no matching protocols are found
