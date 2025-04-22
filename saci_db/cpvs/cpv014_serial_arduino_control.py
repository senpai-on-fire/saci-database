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
                    "Reverse-engineer the CPS firmware to determine if the serial interface is vulnerable to command injection.",
                    "Identify if the firmware has failsafe mechanisms to recover from malicious serial commands.",
                    "Analyze the CPS control logic to assess how malicious serial commands can perturb the CPS movements during the mission.",
                    "Determine if the firmware implements security mechanisms for the GPS receiver such as GPS encryption, filtering, or authentication.",
                    "Identify if the firmware has failsafe mechanisms to prevent GPS spoofing.",
                    "Analyze the CPS control logic to assess how a static spoofed GPS readings affects the CPS’s operation.",
                    "Create models for the following components: GPS receiver, CPS control logic with serial interface, ESC logic and output, CPS actuators (e.g., motors) controlled by the ESC.",
                    "Report to TA2 any required physical parameters to simulate the CPS dynamics"
                
                "TA2 Exploit Steps",
                    "Simulate the impact of the GPS spoofing to verifty the impact on the CPS.",
                    "Start the simulation by turning-on the CPS and start its intended operation."                    
                    "At arbitrary time x, start the GPS spoofing attack and verify if the CPS remains changes its trajectory.",
                    "Create an automata to simulate a malicious serial command injection on the CPS dynamics.",
                    "Use a fuzzing tool to fuzz the functions and generate a malicious serial commands that manipulate the CPS control during the operation.",
                    "Report the findings to TA3 to conduct the experiments on the physical CPS device",

                "TA3 Exploit Steps",
                    "Use optical imaging tools to catalog all of the components on the CPS.",
                    "Identify which components contained memory that might contain firmware.",
                    "Extract the firmware from the memory component.",
                    "Check if there's a GPS receiver on the CPS.",
                    "Deploy and configure the GPS spoofer (e.g., HackRF) and replace the GPS antenna.",
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