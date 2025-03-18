from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import ESC, Serial

from saci_db.vulns.lack_serial_auth_vuln import LackSerialAuthenticationVuln

from saci.modeling.communication import ExternalInput
from saci.modeling.state import GlobalState

from saci.modeling.attack.serial_attack_signal import SerialAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

class SerialESCResetCPV(CPV):
    
    NAME = "The ESC Reset via Serial Interface"

    def __init__(self):
        super().__init__(
            required_components=[
                Serial(),
                ESC(),
            ],
            entry_component = Serial(),
            exit_component = ESC(),

            vulnerabilities =[LackSerialAuthenticationVuln()],

            initial_conditions ={
                "Position": "Any",
                "Heading": "Any", 
                "Speed": "Any", 
                "Environment": "Any", 
                "Software state": "On",
                "Operator Supervision": "Any",
                "OperatingMode": "Manual or Mission",
            },
            
            attack_requirements=[
                "physical access",
                "Microprocessor Programmer",
                "1-Wire Serial Interface Adapter",
                "Terminal Emulator Software"
            ],

            attack_vectors = [BaseAttackVector(name="Serial Reset Command Injection", 
                                               signal=SerialAttackSignal(src=ExternalInput(), dst=Serial()),
                                               required_access_level="Physical",
                                                )],

            attack_impacts = [BaseAttackImpact(category='Loss of availability',
                                               description='ESC will repeatedly reset every 3s')],
            exploit_steps=[
                "TA1 Exploit Steps",
                    "Reverse-engineer the ESC firmware to determine if its serial interface is vulnerable to command injection.",
                    "Identify if the ESC firmware has failsafe mechanisms to recover from malicious commands over the serial interface.",
                    "Analyze the ESC control logic how malicious serial commands can manipulate the ESC operation.",
                    "Create models for the following components: ESC with serial interface, Battery, ESC logic and output, Actuators (e.g., motors) controlled by the ESC.",
                    "Report to TA2 any required enrionnemental factors (e.g., temperature) to simulate the battery state."
                
                
                "TA2 Exploit Steps",
                    "Create an automata to simulate a malicious serial command injection on the ESC.",
                    "Use a fuzzing tool to fuzz the functions and generate a malicious serial commands that directly reset the ESC operation.",
                    "Report the findings to TA3 to conduct the experiments on the physical CPS device",

                "TA3 Exploit Steps",
                    "Use optical imaging tools to catalog all of the components on the CPS.",
                    "Identify which components contained memory that might contain ESC firmware.",
                    "Extract the ESC firmware from the ESC memory component.",
                    "Connect to the ESC via a USB-TTL serial adapter using a terminal emulator with a baud rate of 38400.",
                    "Arm the ESC and start the motor.",
                    "Send a throttle command of zero to initialize the motor/firmware state.",
                    "Send a throttle command to engage the motor and observe that the motor begins to spin.",
                    "Send a throttle command of zero to stop the motor.", 
                    "Reset power to ESC. In theory this should not be necessary, but in practice values could not be set reliably if a non-zero throttle had been commanded within the same power cycle.",
                    "Send the data following data to set the prot_volt configuration value:",
                    "Send the data following data to set the prot_cells configuration value:",
                    "Save the configuration changes",
                    "Repeat steps 1 & 2 to engage the motor.",
                    "Observe that the motor either begins to spin and stops within three seconds or will not start at all"
                ],
                
            associated_files=[],
            reference_urls=["https://github.com/senpai-on-fire/Greensight1A-esc-CPVs/blob/main/CPV004/HII-GSP1AESC01NR017-CPV004-20241003.docx"]
        )
    
    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass