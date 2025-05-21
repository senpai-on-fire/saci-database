from typing import List

from saci.modeling.device import Serial, Telemetry, Controller, GPSReceiver, ESC, PWMChannel, Motor, Serial
from saci.modeling import CPV

from saci_db.vulns.gps_spoofing_vuln import GPSSpoofingVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln
from saci_db.vulns.lack_gps_filtering_vuln import LackGPSFilteringVuln

from saci.modeling.communication import ExternalInput
from saci.modeling.state import GlobalState

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.gps_attack_signal import GPSAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact


class GPSSpoofingStaticCPV(CPV):
    
    NAME = "The GPS Spoofing for Keeping the CPS in a Static Position"
    
    def __init__(self):
        super().__init__(
            required_components=[
                GPSReceiver(),
                Serial(),
                Controller(),
                Controller(),
                PWMChannel(), 
                ESC(),
                Motor(),
            ],
            entry_component=GPSReceiver(),
            exit_component=Motor(),
            
            vulnerabilities=[GPSSpoofingVuln(), ControllerIntegrityVuln(), LackGPSFilteringVuln()],
            
            goals=[],
            
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any", 
                "Environment": "Any", 
                "RemoteController": "On", 
                "CPSController": "Moving",
                "Operating mode": "Mission",
            },
            
            # TODO: We also want to specify the signal data
            # TODO: Modulate the access level and configuration
            attack_requirements = ["GPS Spoof device (e.g., HackRF SDR)"],
            attack_vectors= [BaseAttackVector(name="GPS Spoofing Signals Injection", 
                                               signal=GPSAttackSignal(src=ExternalInput(), dst=GPSSpoofingVuln().component, modality="gps_signals"),
                                               required_access_level="Remote",
                                               configuration={"duration": "permanent"},
                                                )],
            attack_impacts= [BaseAttackImpact(category='Loss of control',
                                               description='CPS drives in circles without stopping')],
            
            exploit_steps= [
                "TA1 Exploit Steps",
                    "Reverse-engineer the CPS firmware to determine if it implements security mechanisms such as GPS encryption, filtering, or authentication.",
                    "Identify if the firmware has failsafe mechanisms to prevent GPS spoofing.",
                    "Analyze the CPS control logic to assess how a static spoofed GPS readings affects the CPS’s operation.",
                    "Create models for the following components: GPS receiver, CPS control logic, ESC logic and output, CPS actuators (e.g., motors) controlled by the ESC.",
                    "Report to TA2 any required physical parameters to simulate the CPS dynamics"
                
                
                "TA2 Exploit Steps",
                    "Simulate the impact of the GPS spoofing to verifty the impact on the CPS.",
                    "Start the simulation by turning-on the CPS and start its intended operation."                    
                    "At arbitrary time x, start the GPS spoofing attack into and verify if the CPS remains at static position.",
                    "Report the findings to TA3 to conduct the experiments on the physical CPS device",

                "TA3 Exploit Steps",
                    "Use optical imaging tools to catalog all of the components on the CPS.",
                    "Identify which components contained memory that might contain firmware.",
                    "Extract the firmware from the memory component.",
                    "Check if there's a GPS receiver on the CPS. "
                    "Deploy a GPS spoofer (e.g., HackRF) near the target's vicinity.",
                    "Send modified GPS signals targeting the CPS's receiver.",
                    "Observe the manipulated localization output.",
                    ],
            
            associated_files = [],
            reference_urls = ["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV007"],
        )
        
    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass