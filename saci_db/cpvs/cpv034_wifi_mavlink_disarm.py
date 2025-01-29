from typing import List, Type

from saci.modeling import CPV

from saci_db.vulns.lack_wifi_auth_vuln import LackWifiAuthenticationVuln
from ..vulns.mavlink_mitm_vuln import MavlinkMitmVuln

from saci.modeling.communication import ExternalInput

from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci_db.devices.px4_quadcopter_device import PX4Controller
from saci.modeling.device import Wifi, TelemetryHigh, Mavlink, ESC, PWMChannel, MultiCopterMotor
from saci.modeling.state import GlobalState

class MavlinkDisarmCPV(CPV):
    
    NAME = "The Mavlink Disram via Wifi"

    def __init__(self):
        super().__init__(
            required_components=[
                Wifi(),
                Mavlink(),
                TelemetryHigh(),            
                PX4Controller(),   
                PWMChannel(),  
                ESC(),
                MultiCopterMotor(),
            ],
            entry_component = Mavlink(),
            exit_component = MultiCopterMotor(),

            vulnerabilities =[LackWifiAuthenticationVuln(), MavlinkMitmVuln()],

            initial_conditions ={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any (>0)",
                "Environment": "Any",
                "RemoteController": "On",
                # double check this 
                "CPSController": "Moving",
                "Operating mode": "flying"
            },
            
            attack_requirements=[
                "Computer",
                "namp",
                "mavproxy",
            ],

            attack_vectors = [BaseAttackVector(name="MavLink Packets Injection", 
                                               signal=PacketAttackSignal(src=ExternalInput(), dst=TelemetryHigh()),
                                               required_access_level="Proximity",
                                               configuration={"protocol":"UDP","port":"14550","command":"disarm"},
                                                )],
            attack_impacts = [BaseAttackImpact(category='Physical Impact',
                                               description='The CPS crashes into the ground')],
            exploit_steps=[
                "Identify the IP addresses and ports of the controller and the CPS",
                "Perform ARP spoofing",
                "Send a DISARM MAVLink command"
                ],
                
            associated_files=[],
            #TODO: add a video link! 
            reference_urls=["https://ieeexplore.ieee.org/document/7575381", "Add a video link"]
        )

    
    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass