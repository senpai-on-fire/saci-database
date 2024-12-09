from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import Controller, Wifi, Controller, CyberComponentBase, Mavlink, ESC
from saci_db.vulns.wifi_lack_auth_vuln import LackWifiAuthenticationVuln
from ..vulns.mavlink_mitm_vuln import MavlinkVuln01
from saci.modeling.communication import ExternalInput

from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci_db.devices.px4_quadcopter_device import GCSTelemetry, PX4Controller
from saci.modeling.device import MultiCopterMotor
from saci.modeling.state import GlobalState

class MavlinkDisarmCPV(CPV):
    
    NAME = "Mavlink Disram CPV"

    def __init__(self):
        super().__init__(
            required_components=[
                Mavlink(),
                PX4Controller(),
                ESC(),
                MultiCopterMotor()
            ],
            entry_component = GCSTelemetry(),
            exit_component = MultiCopterMotor(),

            vulnerabilities =[LackWifiAuthenticationVuln(), MavlinkVuln01()],

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
                                               signal=PacketAttackSignal(src=ExternalInput(), dst=GCSTelemetry()),
                                               required_access_level="Proximity",
                                               configuration={"protocol":"UDP","port":"14550","command":"disarm"},
                                                )],
            attack_impacts = [BaseAttackImpact(category='Physical Impact',
                                               description='The CPS crashes into the ground')],
            exploit_steps=[
                "1. Identify the IP addresses and ports of the controller and the CPS",
                "2. Perform ARP spoofing",
                "3. Send a DISARM MAVLink command"
                ],
                
            associated_files=[],
            #TODO: add a video link! 
            reference_urls=["add alink the video we have"]
        )

    
    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass