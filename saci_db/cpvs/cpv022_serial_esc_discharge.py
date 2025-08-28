
from saci.modeling import CPV
from saci.modeling.device import BMS, Battery, ESC, Serial
from saci.modeling.state import GlobalState

from saci_db.vulns.lack_serial_auth_vuln import LackSerialAuthenticationVuln

from saci.modeling.attack.serial_attack_signal import SerialAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.communication import ExternalInput


class SerialESCDischargeCPV(CPV):
    NAME = "The Keep Battery Discharging via Serial CPV"

    def __init__(self):
        super().__init__(
            
            required_components=[
                Serial(), # This is the entry component (Required)
                ESC(), # This is a required vulnerable component (Required)
                BMS(), # This is a required vulnerable component (Required)
                Battery(), # This is the exit component (Required)
            ],
            
            entry_component=Serial(),
            exit_component=Battery(),
            
            vulnerabilities=[LackSerialAuthenticationVuln()],
            
            goals=[],
            
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any",
                "Environment": "Any",
                "BMS": "On",
                "ESC": "On",
                "OperatingMode": "Manual or Mission",
            },
            
            attack_vectors=[
                BaseAttackVector(
                    name="Serial Prot_Cells Discharge Command Injection",
                    signal=SerialAttackSignal(
                        src=ExternalInput(), dst=Serial(), data="set prot_cells 1"
                    ),
                    required_access_level="Physical",
                ),
            ],
            
            attack_requirements=["Computer", "USB-TTL Serial Adapter with 3.3v logic"],
            
            attack_impacts=[
                BaseAttackImpact(
                    category="Damage to Property",
                    description="ESC will not limit battery discharge",
                ),
            ],
            
            exploit_steps=[
                "TA1 Exploit Steps",
                    "Reverse-engineer the ESC firmware to determine if its serial interface is vulnerable to command injection.",
                    "Identify if the ESC firmware has failsafe mechanisms to recover from malicious commands over the serial interface.",
                    "Analyze the ESC control logic and determine how malicious serial commands can manipulate the ESC battery management.",
                    "Create models for the following components: ESC with serial interface, Battery, ESC logic and output, Actuators (e.g., motors) controlled by the ESC.",
                    "Report to TA2 any required environmental factors (e.g., temperature) to simulate the battery state."
                "TA2 Exploit Steps",
                    "Create an automata to simulate a malicious serial command injection on the ESC.",
                    "Use a fuzzing tool to fuzz the functions and generate a malicious serial commands that manipulated the battery discharge by the ESC.",
                    "Report the findings to TA3 to conduct the experiments on the physical CPS device",
                "TA3 Exploit Steps",
                    "Connect the USB-TTL Serial Adapter to the RC_1 test point on the ESC.",
                    "Send the Serial Command 'set prot_cells 1' to the ESC.",
            ],
            
            associated_files=[],
            reference_urls=[
                "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV005",
                "https://github.com/neoxic/ESCape32/wiki/Configuration#cli-command-line-interface",
            ],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
