from typing import List, Type
from saci.modeling import CPV
from saci.modeling.device import Motor, ESC, Debug

from saci.modeling.communication import ExternalInput

from saci_db.vulns.lack_serial_auth_vuln import LackSerialAuthenticationVuln

from saci.modeling.attack.serial_attack_signal import SerialAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.state import GlobalState

class DebugESCFlashCPV(CPV):
    
    NAME = "The ESC Flash via Debug Interface"

    def __init__(self):
        super().__init__(
            required_components=[
                Debug(),
                ESC(),
                Motor(),
            ],
            entry_component = Debug(),
            exit_component = Motor(),

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
                "USB-TTL Serial Adapter",
                "Terminal Emulator Software",
                "script used to attack"
            ],

            attack_vectors = [BaseAttackVector(name="Debug Commands Injection", 
                                               signal=SerialAttackSignal(src=ExternalInput(), dst=Debug(), data = "specific sequence of bytes"), # command: need to check what the specific sequence of bytes is
                                               required_access_level="Physical",
                                                )],
            attack_impacts = [BaseAttackImpact(category='Denial of control',
                                               description='Motor stops spinning')],
            exploit_steps=[
                "TA1 Exploit Steps",
                    "Reverse-engineer the ESC firmware to determine if its debug interface is vulnerable to command injection.",
                    "Identify if the ESC firmware has failsafe mechanisms to recover from malicious commands over the debug interface.",
                    "Analyze the ESC control logic how malicious debug commands can manipulate the motor's throttle.",
                    "Create models for the following components: ESC with debug interface, Battery, ESC logic and output, Actuators (e.g., motors) controlled by the ESC.",
                    "Report to TA2 any required enrionnemental factors (e.g., temperature) to simulate the battery state."
                
                "TA2 Exploit Steps",
                    "Create an automata to simulate a malicious debug command injection on the BMS.",
                    "Use a fuzzing tool to fuzz the functions and generate a malicious debug commands that directly manipulate the motor's spinning.",
                    "Report the findings to TA3 to conduct the experiments on the physical CPS device",

                "TA3 Exploit Steps",
                    "Use optical imaging tools to catalog all of the components on the CPS.",
                    "Identify which components contained memory that might contain ESC firmware.",
                    "Extract the ESC firmware from the ESC memory component.",
                    "Send a throttle command of zero to initialize the motor/firmware state.",   
                    "Send a throttle command to engage the motor.",              
                    "Observe that the motor begins to spin.",    
                    "Send the data following data to enter bootloader mode.",    
                    "Observe that the motor stops spinning.",
                ],
                
            associated_files=[],
            reference_urls=["https://github.com/senpai-on-fire/Greensight1A-esc-CPVs/blob/main/CPV002/HII-GSP1AESC01NR017-CPV002-20240930.docx"]
        )
    
    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass