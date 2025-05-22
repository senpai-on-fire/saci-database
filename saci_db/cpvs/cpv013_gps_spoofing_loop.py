from typing import List

from saci.modeling.device import Controller, Serial, GPSReceiver, Motor, PWMChannel, ESC, CANBus, CANTransceiver, CANShield
from saci.modeling import CPV 

from saci_db.vulns.gps_spoofing_vuln import GPSSpoofingVuln
from saci_db.vulns.lack_gps_filtering_vuln import LackGPSFilteringVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln
from saci_db.vulns.lack_serial_auth_vuln import LackSerialAuthenticationVuln

from saci.modeling.communication import ExternalInput

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.gps_attack_signal import GPSAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.state import GlobalState

class GPSSpoofingLoopCPV(CPV):
    
    NAME = "The GPS Spoofing for Keeping the CPS Position Dead Loop"
    
    def __init__(self):
        super().__init__(
            required_components=[
                GPSReceiver(),
                Serial(),
                Controller(),
                CANTransceiver(),
                CANBus(),
                CANShield(),
                Controller(),
                PWMChannel(), 
                ESC(),
                Motor(),
            ],
            # TODO: this one contains multiple entry:
            # we need to first sending numerical input to the controller
            # then we need to spoof the GPS signal to the GPS receiver
            entry_component=GPSReceiver(),
            exit_component=Motor(),
            
            vulnerabilities=[GPSSpoofingVuln(), LackGPSFilteringVuln(), ControllerIntegrityVuln(), LackSerialAuthenticationVuln()],
            
            goals=[],
            
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any", 
                "Environment": "Any", 
                "RemoteController": "On", 
                "CPSController": "Idle",
                "OperatingMode": "Manual or Mission",
            },
            
            # TODO: We also want to specify the signal data
            # TODO: Modulate the access level and configuration
            attack_requirements = ["GPS Spoof device (e.g., HackRF SDR)"],
            attack_vectors= [BaseAttackVector(name="GPS Spoofing Signal Injection", 
                                               signal=GPSAttackSignal(src=ExternalInput(), dst=GPSReceiver()),
                                               required_access_level="Remote",
                                               configuration={"duration": "permanent"},
                                                )],
            attack_impacts= [BaseAttackImpact(category='Deny of Service',
                                              description='The CPS’s behavior can be altered in unintended ways, such as stopping mid-sequence, moving intermittently, or executing a sequence not commanded by the operator')],
            
            exploit_steps = [
                "TA1 Exploit Steps",
                    "Reverse-engineer the CPS firmware to determine if it implements security mechanisms such as GPS encryption, filtering, or authentication.",
                    "Identify if the firmware has failsafe mechanisms to prevent GPS spoofing.",
                    "Analyze the CPS control logic to understand how a a spoofed GPS readings affects the CPS’s operation.",
                    "Create models for the following components: GPS receiver, CPS control logic, ESC logic and output, CPS actuators (e.g., motors) controlled by the ESC.",
                    "Report to TA2 any required physical parameters to simulate the CPS dynamics"
                
                "TA2 Exploit Steps",
                    "Simulate the impact of the GPS spoofing to verifty the impact on the CPS.",
                    "Start the simulation by turning-on the CPS and start its intended operation."                    
                    "At arbitrary time x, start the GPS spoofing attack into and verify if the CPS remains at static position.",
                    "Use a fuzzing tool, find which command will trigger a loop state in the CPS device."
                    "Report the findings to TA3 to conduct the experiments on the physical CPS device",

                "TA3 Exploit Steps",
                    "Use optical imaging tools to catalog all of the components on the CPS.",
                    "Identify which components contained memory that might contain firmware.",
                    "Extract the firmware from the memory component.",
                    "Check if there's a GPS receiver on the CPS. "
                    "Configure the HackRF device and replace the GPS antenna.",
                    "Transmit the spoofed GPS signal using specific commands.",
                    "Connect the RemoteController to a computer via USB.",
                    "In the idle state the CPS should repeatedly print readings from the digital compass in the form of one floating point number per line."
                    "With the CPS in the idle state, enter the number 77 into the terminal."
                    "Observer the CPS does not begin to drive, and no longer responds to requests in the terminal or through the webserver."
                ],
            
            associated_files = [],
            reference_urls = ["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV013"],
        )
        
    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass