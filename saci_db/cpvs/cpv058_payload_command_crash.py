from saci.modeling import CPV
from saci.modeling.device import Serial, Motor
from saci.modeling.communication import ExternalInput

from saci.modeling.attack.payload_firmware_attack import PayloadFirmwareAttack
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci_db.vulns.payload_firmware_vuln import FirmwarePayloadVuln

from saci_db.devices.propriety_quadcopter_device import ProprietyController

from saci.modeling.device import Controller


class PayloadCrashCommandCPV(CPV):
    NAME = "The Drone Mid-Flight Crash Exploit"

    def __init__(self):
        super().__init__(
            required_components=[
                Serial(),  # This is the entry component (Required)
                Controller(),  # This is the main controller where the firmware is hosted (Required)
                # PWMChannel(), # Removed since the PWMChannel is just a passthrough for the CPV (Not Required)
                # ESC(), # Removed since the ESC is just a passthrough for the CPV (Not Required)
                Motor(),  # This is the exit component + Changed to Motor() for generalization (Required)
            ],
            entry_component=Serial(),
            exit_component=Motor(),
            vulnerabilities=[FirmwarePayloadVuln()],
            goals=["Crash the drone mid-flight by exploiting firmware vulnerabilities"],
            initial_conditions={
                "Drone State": "In Flight",
                "GNSS Connection": "Active",
                "Remote Controller": "Active",
                "Firmware": "Unsecured",
                "OperatingMode": "Manual or Mission",
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
                        dst=ProprietyController(),  # Add the binary abstraction here
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
                "TA1 Exploit Steps",
                "Implement a model to simulate a firmware paayload attack on the CPS dynamic.The model must include:",
                "    - Control logic algorithm.",
                "    - GPS receiver sensor.",
                "    - Any required physical parameters to simulate CPS dynamics.",
                "    - Electronic speed controller logic and output.",
                "    - CPS actuators (e.g., motors) controlled by the ESC.",
                "TA2 Exploit Steps",
                "Simulate the CPS dynamics after injecting the payload",
                "Refine the malicious payload based on TA1 observations to trigger the desired attack impact",
                "TA3 Exploit Steps",
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
