
from saci.modeling import CPV
from saci.modeling.device import ESC, SMBus, BMS

from saci_db.vulns.lack_serial_auth_vuln import LackSerialAuthenticationVuln

from saci.modeling.communication import ExternalInput
from saci.modeling.state import GlobalState

from saci.modeling.attack.serial_attack_signal import SerialAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact


class SMBusBatteryShutdownCPV(CPV):
    NAME = "The Battery Shutdown via SMBus"

    def __init__(self):
        super().__init__(
            
            required_components=[
                SMBus(), # This is the entry component (Required)
                BMS(), # This is a required vulnerable component (Required)
                ESC(), # This is the exit component (Required)
            ],
            
            entry_component=SMBus(),
            exit_component=ESC(),
            
            vulnerabilities=[LackSerialAuthenticationVuln()],
            
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any",
                "Environment": "Any",
                "Software state": "Any",
                "Operator Supervision": "Any",
                "OperatingMode": "Manual or Mission",
            },
            
            attack_requirements=[
                "BQStudio version 1.3.127",
                "TI EV2400 EVM Interface board",
            ],
            
            attack_vectors=[
                BaseAttackVector(
                    name="SMBus Shutdown Command Injection",
                    signal=SerialAttackSignal(src=ExternalInput(), dst=SMBus()),
                    required_access_level="Physical",
                )
            ],
            
            attack_impacts=[
                BaseAttackImpact(
                    category="Loss of control",
                    description="system does not provide power to subsystem",
                )
            ],
            
            exploit_steps=[
                "TA1 Exploit Steps",
                    "Reverse-engineer the BMS firmware to determine if its serial interface is vulnerable to command injection.",
                    "Identify if the BMS firmware has failsafe mechanisms to recover from malicious serial commands.",
                    "Analyze the battery management system to assess how malicious serial commands can manipulate the ESC and battery.",
                    "Create models for the following components: BMS with serial interface, Battery, ESC logic and output, Actuators (e.g., motors) controlled by the ESC.",
                    "Report to TA2 any required environmental factors (e.g., temperature) to simulate the battery state."
                "TA2 Exploit Steps",
                    "Create an automata to simulate a malicious serial command injection on the BMS.",
                    "Use a fuzzing tool to fuzz the functions and generate a malicious serial commands that directly manipulate the battery, ESC, and battery.",
                    "Report the findings to TA3 to conduct the experiments on the physical CPS device",
                "TA3 Exploit Steps",
                    "Use optical imaging tools to catalog all of the components on the CPS.",
                    "Identify which components contained memory that might contain firmware.",
                    "Extract the BMS firmware from the BMS memory component.",
                    "Connect an SMBus cable between the SMBus connector on the EV2400 and J3 on the battery monitor board",
                    "Power system on using only battery power",
                    "Observe the system is operational, LEDs on the ESC are on",
                    "Open BQStudio",
                    "If the BQ40Z80 isn't detected automatically BQStudio will prompt the user to select a device",
                    "Once connected through BQStudio, observe that the BQ40Z80 status is displayed on the screen",
                    "In the commands window click SHUTDOWN twice",
                    "The BQ40Z80 will enter shutdown mode disconnecting the power from the system",
                    "Observe the ESC board LEDs are disabled.",
            ],
            
            associated_files=[],
            reference_urls=[
                "https://github.com/senpai-on-fire/Greensight1A-esc-CPVs/blob/main/CPV001/HII-GSP1AESC01NR017-CPV001-20240926.docx"
            ],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
