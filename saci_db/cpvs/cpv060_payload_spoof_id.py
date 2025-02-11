from saci.modeling import CPV
from saci.modeling.device import (PWMChannel, ESC, MultiCopterMotor)
from saci.modeling.communication import ExternalInput

from saci.modeling.attack.payload_firmware_attack import PayloadFirmwareAttack
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci_db.vulns.payload_firmware_vuln import FirmwarePayloadVuln

from saci_db.devices.propriety_quadcopter_device import ProprietyController

class PayloadSpoofDroneIDCPV(CPV):
    
    NAME = "The Spoof Drone Identifier for Masking Identity"

    def __init__(self):
        super().__init__(
            required_components=[
                ProprietyController(),
                PWMChannel(),
                ESC(),
                MultiCopterMotor(),
            ],
            entry_component=ProprietyController(),
            exit_component=MultiCopterMotor(),
            
            vulnerabilities=[FirmwarePayloadVuln],
            
            goals=["Spoof the drone’s identifier to mask its identity"],
            
            initial_conditions={
                "Drone State": "On Ground or In Flight",
                "Firmware": "Unsecured",
                "DroneID Protocol": "Active",
                "OperatingMode": "Manual or Mission",
            },
            
            attack_requirements=[
                "Physical access to the drone’s controller or configuration.",
                "Ability to modify DroneID-related firmware or settings.",
            ],
            
            attack_vectors=[
                BaseAttackVector(
                    name="Identifier Spoofing",
                    signal=PayloadFirmwareAttack(
                        src=ExternalInput(),
                        dst=ProprietyController(), # Add the binary abstraction here
                        modality="fimware payload",
                    ),
                    required_access_level="Physical Access",
                    configuration={"modifications": "Modify Drone Serial Number"},
                )
            ],
            
            attack_impacts=[
                BaseAttackImpact(
                    category="Anonymity",
                    description=(
                        "The attacker alters the drone's identifier (e.g., serial number) to mask its identity, complicating tracking and accountability."
                    ),
                ),
            ],
            
            exploit_steps=[
                "Gain physical access to the drone’s controller or firmware.",
                "Extract and analyze the DroneID firmware or configuration files.",
                "Modify the unique identifier fields (e.g., serial number).",
                "Deploy the modified firmware back to the drone.",
                "Verify that the drone now broadcasts a spoofed identifier.",
            ],
            
            associated_files=[],
            
            reference_urls=[
                "https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_f217_paper.pdf",
            ],
        )
        
        self.goal_state = ["Drone broadcasts a spoofed identifier, masking its identity"]

    def in_goal_state(self, state):
        return state.get("DroneIdentifier") == "Spoofed"
