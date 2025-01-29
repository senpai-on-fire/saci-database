from saci.modeling import CPV
from saci.modeling.device import (PWMChannel, ESC, MultiCopterMotor)
from saci.modeling.communication import ExternalInput

from saci.modeling.attack.payload_firmware_attack import PayloadFirmwareAttack
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci_db.vulns.payload_firmware_vuln import FirmwarePayloadVuln

from saci_db.devices.propriety_quadcopter_device import ProprietyQuadcopter

class PayloadCrashCommandCPV(CPV):

    NAME = "Drone Mid-Flight Crash Exploit"

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
            
            goals=["Crash the drone mid-flight by exploiting firmware vulnerabilities"],
            
            initial_conditions={
                "Drone State": "In Flight",
                "GNSS Connection": "Active",
                "Remote Controller": "Active",
                "Firmware": "Unsecured",
            },
            
            attack_requirements=[
                "Physical access to the drone to analyze and modify firmware.",
                "Ability to deploy a malicious payload to the drone’s firmware.",
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
                    configuration={"payload": "Crash Command Injection"},
                )
            ],
            
            attack_impacts=[
                BaseAttackImpact(
                    category="Physical Damage",
                    description=(
                        "The attacker manipulates the drone's firmware to execute a crash command, causing the drone to lose control and fall mid-flight."
                    ),
                ),
            ],
            
            exploit_steps=[
                "Gain physical access to the drone and extract its firmware.",
                "Analyze the firmware for vulnerabilities allowing arbitrary code execution.",
                "Inject a malicious payload to execute a crash command mid-flight.",
                "Deploy the modified firmware to the drone and initiate a flight.",
                "Trigger the crash command to force the drone to fall mid-flight.",
            ],
            
            associated_files=[],
            
            reference_urls=[
                "https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_f217_paper.pdf",
            ],
        )
        
        self.goal_state = ["Drone crashes mid-flight due to injected commands"]

    def in_goal_state(self, state):
        return state.get("DroneStatus") == "Crashed"
