from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (Motor, ESC, Serial) 
from saci.modeling.state import GlobalState

from saci_db.vulns.lack_serial_auth_vuln import LackSerialAuthenticationVuln

from saci.modeling.attack.serial_attack_signal import SerialAttackSignal 
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.communication import ExternalInput

class SerialOverheatingCPV(CPV):
    
    NAME = "The Overheating Motors via Serial Interface"

    def __init__(self):
        serial_vuln = LackSerialAuthenticationVuln()
        super().__init__(
            required_components=[
                Serial(),
                ESC(),
                Motor(),
            ],

            entry_component=Serial(),
            exit_component=Motor(),

            vulnerabilities=[serial_vuln],

            goals = [],

            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any",
                "Environment": "Any",
                "BMS": "On",
                "ESC": "On",
                "OperatingMode": "Manual or Mission",
            },

            attack_vectors = [BaseAttackVector(name='Serial Duty_speed_up Command Injection',
                                               signal=SerialAttackSignal(src=ExternalInput(), dst=Serial(), data='set duty_spup 100'),
                                               required_access_level='Physical',
                                               ),],

            attack_requirements = ['Computer', 'USB-TTL Serial Adapter with 3.3v logic'],
            attack_impacts = [BaseAttackImpact(category='Damage to Property',
                                               description='Motors will overheat'),],
            
            exploit_steps=[
                "TA1 Exploit Steps",
                    "Reverse-engineer the ESC firmware to determine if its serial interface is vulnerable to command injection.",
                    "Identify if the ESC firmware has failsafe mechanisms to recover from malicious commands over the serial interface.",
                    "Analyze the ESC control logic and determine how malicious serial commands can manipulate the duty speedup of the ESC.",
                    "Create models for the following components: ESC with serial interface, Battery, ESC logic and output, Actuators (e.g., motors) controlled by the ESC.",
                    "Report to TA2 any required enrionnemental factors (e.g., temperature) to simulate the battery state."
                
                "TA2 Exploit Steps",
                    "Create an automata to simulate a malicious serial command injection on the ESC.",
                    "Use a fuzzing tool to fuzz the functions and generate a malicious serial commands that can trigger change the duty speeded of the ESC.",
                    "Report the findings to TA3 to conduct the experiments on the physical CPS device",

                "TA3 Exploit Steps",
                    "Connect the USB-TTL Serial Adapter to the RC_1 test point on the ESC.",
                    "Send a Serial Command that sets Duty Cycle during speed up to 100.",
            ],

            associated_files = [],
            reference_urls = ["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV008",
                              "https://github.com/neoxic/ESCape32/wiki/Configuration#cli-command-line-interface"],
        )


    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
