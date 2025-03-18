from typing import List

from saci.modeling.device import Controller, Serial, PWMChannel, Motor, ESC
from saci.modeling import CPV
from saci.modeling.state import GlobalState

from saci_db.vulns.lack_serial_auth_vuln import LackSerialAuthenticationVuln

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.gps_attack_signal import GPSAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.communication import ExternalInput

class SerialArduinoControlCPV(CPV):
    
    NAME = "The Arduino Control via Serial Interface"
    
    def __init__(self):
        super().__init__(
            required_components=[
                Serial(),
                Controller(),
                Controller(),
                PWMChannel(), 
                ESC(),
                Motor(),
            ],
            entry_component=Serial(),
            exit_component=Motor(),
            
            vulnerabilities=[LackSerialAuthenticationVuln],
            
            goals=[],
            
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any", 
                "Environment": "Any", 
                "RemoteController": "On", 
                "CPSController": ["Moving, Idle"],
                "OperatingMode": "Manual or Mission",
            },
            
            attack_requirements = ["Computer", "USB-C cable"],
            attack_vectors= [BaseAttackVector(name="Serial Arduino Commands Injection", 
                                               signal=GPSAttackSignal(src=ExternalInput(), dst=Serial()),
                                               required_access_level="Physical",
                                               configuration={"duration": "one-time"},
                                                )],
            attack_impacts= [BaseAttackImpact(category='Control Manipulation',
                                              description='The CPS’s behavior can be altered in unintended ways, such as stopping mid-sequence, moving intermittently, or executing a sequence not commanded by the operator')],
            
            exploit_steps = [
                "TA1 Exploit Steps",
                
                "TA2 Exploit Steps",

                "TA3 Exploit Steps",
                    "Configure the HackRF device and replace the GPS antenna.",
                    "Transmit the spoofed GPS signal using specific commands.",
                    "Connect the Arduino Uno R4 to a computer via USB.",
                    "Open a terminal emulator or use provided scripts to send commands.",
                    "Input specific commands:",
                    "    - 77: Initiates a pre-programmed driving sequence.",
                    "    - 66: Interrupts the sequence, stopping the rover.",
                    "    - 55: Causes intermittent movements with brief motor engagements.",
                    "Observe the corresponding effects on the CPS."
            ],
            
            associated_files = [],
            reference_urls = ["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV014"],
        )
        
    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass