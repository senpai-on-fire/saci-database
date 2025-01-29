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