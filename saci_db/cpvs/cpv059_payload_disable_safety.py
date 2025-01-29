from saci.modeling import CPV
from saci.modeling.device import (PWMChannel, ESC, MultiCopterMotor)
from saci.modeling.communication import ExternalInput

from saci.modeling.attack.payload_firmware_attack import PayloadFirmwareAttack
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci_db.vulns.payload_firmware_vuln import FirmwarePayloadVuln

from saci_db.devices.propriety_quadcopter_device import ProprietyQuadcopter

class PayloadDisableSafetyCPV(CPV):

    NAME = "Disable Safety Features for Unauthorized Drone Operation"

    def __init__(self):
        super().__init__(
            required_components=[
                ProprietyQuadcopter(),
                PWMChannel(),
                ESC(),
                MultiCopterMotor(),
            ],
            entry_component=ProprietyQuadcopter(),
            exit_component=MultiCopterMotor(),
            
            vulnerabilities=[FirmwarePayloadVuln()],
            
            goals=["Disable geofencing and altitude restrictions to enable unauthorized flight"],
            
            initial_conditions={
                "Drone State": "On Ground or In Flight",
                "GNSS Connection": "Active",
                "Firmware": "Unsecured",
            },
            
            attack_requirements=[
                "Physical access to modify firmware or configuration files.",
                "Ability to disable safety settings without authentication.",
            ],

            attack_vectors=[
                BaseAttackVector(
                    name="Firmware Exploitation",
                    signal=PayloadFirmwareAttack(
                        src=ExternalInput(),
                        dst=ProprietyQuadcopter(), # Add the binary abstraction here
                        modality="fimware payload",
                    ),
                    required_access_level="Physical Access",
                    configuration={"payload": "Disable Safety Features"},
                )
            ],
            
            attack_impacts=[
                BaseAttackImpact(
                    category="Unauthorized Flight Operation",
                    description=(
                        "The attacker disables geofencing, altitude limits, or other safety features, enabling the drone to fly into restricted or dangerous areas."
                    ),
                ),
            ],
            
            exploit_steps=[
                "Gain physical access to the drone to extract its firmware or configuration files.",
                "Identify and modify the sections controlling geofencing or altitude limits.",
                "Deploy the modified firmware or configuration back to the drone.",
                "Verify that the drone's safety mechanisms are disabled.",
                "Operate the drone in restricted airspace or at unauthorized altitudes.",
            ],
            
            associated_files=[],
            
            reference_urls=[
                "https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_f217_paper.pdf",
            ],
        )
        
        self.goal_state = ["Safety features are disabled, allowing unrestricted drone operation"]

    def in_goal_state(self, state):
        return state.get("SafetyFeatures") == "Disabled"
