from saci.modeling import CPV
from saci.modeling.device import PWMChannel, ESC, MultiCopterMotor, Serial, Motor
from saci.modeling.communication import ExternalInput

from saci.modeling.attack.payload_firmware_attack import PayloadFirmwareAttack
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci_db.vulns.payload_firmware_vuln import FirmwarePayloadVuln

from saci_db.devices.propriety_quadcopter_device import ProprietyController

from saci.modeling.device import Controller

class PayloadDisableSafetyCPV(CPV):
    NAME = "The Disable Safety Features for Unauthorized Drone Operation"

    def __init__(self):
        super().__init__(
            
            required_components=[
                Serial(), # This is the entry component (Required)
                Controller(), # This is the main controller where the firmware is hosted (Required)
                # PWMChannel(), # Removed since the PWMChannel is just a passthrough for the CPV (Not Required)
                # ESC(), # Removed since the ESC is just a passthrough for the CPV (Not Required)
                Motor(), # This is the exit component + Changed to Motor() for generalization (Required)
            ],
            
            entry_component=Serial(),
            exit_component=Motor(),
            
            vulnerabilities=[FirmwarePayloadVuln()],
            
            goals=[
                "Disable geofencing and altitude restrictions to enable unauthorized flight"
            ],
            
            initial_conditions={
                "Drone State": "On Ground or In Flight",
                "GNSS Connection": "Active",
                "Firmware": "Unsecured",
                "OperatingMode": "Manual or Mission",
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
                        dst=ProprietyController(),  # Add the binary abstraction here
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
                "TA1 Exploit Steps",
                "Implement a model to simulate a firmware paayload attack on the CPS dynamic.",
                "The model must include:",
                "    - Control logic algorithm.",
                "    - GPS receiver sensor.",
                "    - Any required physical parameters to simulate CPS dynamics.",
                "    - Electronic speed controller logic and output.",
                "    - CPS actuators (e.g., motors) controlled by the ESC.",
                "TA2 Exploit Steps",
                "Simulate the CPS dynamics after injecting the payload",
                "Refine the malicious payload based on TA1 observations to trigger the desired attack impact",
                "TA3 Exploit Steps",
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

        self.goal_state = [
            "Safety features are disabled, allowing unrestricted drone operation"
        ]

    def in_goal_state(self, state):
        return state.get("SafetyFeatures") == "Disabled"
