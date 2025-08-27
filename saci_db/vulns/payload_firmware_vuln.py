import os.path
from clorm import Predicate

from saci.modeling.communication import ExternalInput
from saci.modeling.device import Device, Wifi
from saci.modeling import BaseVulnerability
from saci.modeling.attack.payload_firmware_attack import PayloadFirmwareAttack
from saci.modeling.device.component.cyber.cyber_abstraction_level import (
    CyberAbstractionLevel,
)
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci_db.devices.propriety_quadcopter_device import ProprietyQuadcopter
from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack import BaseCompEffect
from saci_db.devices.propriety_quadcopter_device import ProprietyController


# Predicate to define formal reasoning logic for firmware vulnerabilities
class FirmwareVulnerabilityPred(Predicate):
    pass


class FirmwarePayloadVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            # The PX4Controller component vulnerable to firmware exploits
            component=ProprietyQuadcopter(),
            # Input: Firmware-related issues (e.g., outdated, unverified, or insecure firmware)
            _input=None,
            # Output: Exploited firmware leading to UAV compromise
            output=None,
            # Predicate for reasoning about firmware vulnerabilities
            attack_ASP=FirmwareVulnerabilityPred,
            # Logic rules for evaluating firmware vulnerabilities in formal reasoning
            rulefile=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "firmware_payload_vuln.lp"
            ),
            # List of Associated CWEs:
            associated_cwe=[
                "CWE-306: Missing Authentication for Critical Function",
                "CWE-494: Download of Code Without Integrity Check",
                "CWE-295: Improper Certificate Validation",
                "CWE-1188: Insecure Default Initialization of Resource",
                "CWE-20: Improper Input Validation",
            ],
            attack_vectors=[
                {
                    "attack_vector": [
                        BaseAttackVector(
                            name="Beacon Frame Flooding",
                            signal=PacketAttackSignal(
                                src=ExternalInput(),
                                dst=Wifi(),
                            ),
                            required_access_level="Proximity",
                            configuration={
                                "attack_method": "Flood with beacon frames",
                                "frequency": "High",
                                "target": "UAV Wi-Fi interface",
                                "frame_type": "beacon",
                                "delivery_method": {"broadcast": True, "unicast": True},
                                "injection_timing": "after_legitimate_beacon",
                                "elements": [
                                    "WMM",
                                    "power_constraint",
                                    "t",
                                    "TIM",
                                    "CSA",
                                ],
                                "beacon_interval": "102.4ms",
                            },
                        )
                    ],
                    # List of associated CPVs
                    "related_cpv": ["BeaconFrameFloodingCPV"],
                    # List of associated component-level attack effects
                    "comp_attack_effect": BaseCompEffect(
                        category="Availability",
                        description=(
                            "The attack overwhelms the UAV's Wi-Fi interface with forged beacon frames, preventing association with its controller."
                        ),
                    ),
                    # Steps of exploiting this attack vector
                    "exploit_steps": [
                        "Install the ModWifi framework and aircrack-ng suite.",
                        "Set the Wi-Fi interface to monitoring mode.",
                        "Use airodump-ng to identify the target UAV's Wi-Fi network parameters (SSID, Channel, BSSID).",
                        "Capture and analyze settings in legitimate beacon frames (WMM settings, TIM elements, transmission power constraints).",
                        "Craft malicious beacon frames with manipulated parameters (malicious power constraints, modified TIM and CSA elements, extreme EDCA values).",
                        "Inject forged beacon frames after legitimate ones using the ModWifi framework.",
                        "Monitor UAV responses using airodump-ng or Wireshark, and measure network performance changes.",
                    ],
                    # List of related references
                    "reference_urls": [
                        "https://medium.com/@angelinatsuboi/drone-swarmer-uncovering-vulnerabilities-in-open-drone-id-cdd8d1a23c2c",
                        "https://dl.acm.org/doi/pdf/10.1145/3395351.3399442?casa_token=x2LV35bFGowAAAAA:X9TRtxKCpHQtY1ooiZgr4xszKrAUNb0_7m4JWLMjW-Ttr4Rxc-wtyRysnF4qD03ivfbX3W5OsVLSpQ",
                    ],
                },
                {
                    # Merged Firmware Exploitation attack vectors
                    "attack_vector": [
                        BaseAttackVector(
                            name="Firmware Exploitation",
                            signal=PayloadFirmwareAttack(
                                src=ExternalInput(),
                                dst=ProprietyController(),  # Binary abstraction for the proprietary controller
                                modality="fimware payload",
                            ),
                            required_access_level="Physical Access",
                            configuration={"payload": "Crash Command Injection"},
                        ),
                        BaseAttackVector(
                            name="Firmware Exploitation",
                            signal=PayloadFirmwareAttack(
                                src=ExternalInput(),
                                dst=ProprietyController(),  # Binary abstraction for the proprietary controller
                                modality="fimware payload",
                            ),
                            required_access_level="Physical Access",
                            configuration={"payload": "Disable Safety Features"},
                        ),
                    ],
                    "related_cpv": [
                        "PayloadCrashCommandCPV",
                        "PayloadDisableSafetyCPV",
                    ],
                    "comp_attack_effect": BaseCompEffect(
                        category="Integrity",
                        description=(
                            "The attacker exploits firmware vulnerabilities to manipulate the drone's behavior. In one case, a crash command is injected to force a mid-flight fall, "
                            "while in another, safety features such as geofencing and altitude limits are disabled to allow unauthorized flight operations."
                        ),
                    ),
                    "exploit_steps": [
                        # Exploit steps for Crash Command Injection
                        "1. Crash Command Injection",
                        "Gain physical access to the drone and extract its firmware.",
                        "Analyze the firmware for vulnerabilities that allow arbitrary code execution.",
                        "Inject a malicious payload to execute a crash command mid-flight.",
                        "Deploy the modified firmware to the drone and initiate a flight.",
                        "Trigger the crash command to force the drone to fall mid-flight.",
                        # Exploit steps for Disabling Safety Features
                        "2. Disable Safety Features",
                        "Gain physical access to the drone to extract its firmware or configuration files.",
                        "Identify and modify the sections controlling geofencing or altitude limits.",
                        "Deploy the modified firmware or configuration back to the drone.",
                        "Verify that the drone's safety mechanisms are disabled.",
                        "Operate the drone in restricted airspace or at unauthorized altitudes.",
                    ],
                    "reference_urls": [
                        "https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_f217_paper.pdf"
                    ],
                },
                {
                    "attack_vector": [
                        BaseAttackVector(
                            name="Identifier Spoofing",
                            signal=PayloadFirmwareAttack(
                                src=ExternalInput(),
                                dst=ProprietyController(),  # Binary abstraction for the proprietary controller
                                modality="fimware payload",
                            ),
                            required_access_level="Physical Access",
                            configuration={
                                "modifications": "Modify Drone Serial Number"
                            },
                        )
                    ],
                    "related_cpv": ["PayloadSpoofDroneIDCPV"],
                    "comp_attack_effect": BaseCompEffect(
                        category="Confidentiality",
                        description=(
                            "The attacker alters the drone's identifier (e.g., serial number), masking its true identity and complicating tracking and accountability."
                        ),
                    ),
                    "exploit_steps": [
                        "Gain physical access to the drone’s controller or firmware.",
                        "Extract and analyze the DroneID firmware or configuration files.",
                        "Modify the unique identifier fields (e.g., serial number).",
                        "Deploy the modified firmware back to the drone.",
                        "Verify that the drone now broadcasts a spoofed identifier.",
                    ],
                    "reference_urls": [
                        "https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_f217_paper.pdf"
                    ],
                },
            ],
        )

    def exists(self, device: Device) -> bool:
        """
        Checks if the firmware vulnerability exists in the given device by evaluating its firmware configuration.
        """
        for comp in device.components:
            # Check if the component is a PX4Controller
            if isinstance(comp, ProprietyQuadcopter):
                # Verify high-level properties of the PX4Controller for firmware configuration
                if hasattr(comp, "firmware_status") and comp.firmware_status in [
                    "outdated",
                    "unverified",
                ]:
                    return True  # Vulnerability detected at the high level

                # Check if the PX4Controller has a binary abstraction level
                if CyberAbstractionLevel.BINARY in comp.ABSTRACTIONS:
                    binary_component = comp.ABSTRACTIONS[CyberAbstractionLevel.BINARY]

                    # Verify if the binary abstraction has firmware issues
                    if hasattr(binary_component, "integrity_status"):
                        if binary_component.integrity_status in [
                            "corrupted",
                            "tampered",
                        ]:
                            return True  # Vulnerability detected at the binary level
        return False  # No vulnerability detected
