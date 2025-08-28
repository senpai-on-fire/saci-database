
from saci.modeling import CPV

from saci_db.vulns.lack_wifi_auth_vuln import LackWifiAuthenticationVuln
from ..vulns.mavlink_mitm_vuln import MavlinkMitmVuln

from saci.modeling.communication import ExternalInput

from saci.modeling.device import Controller

from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact


from saci.modeling.device import (
    Wifi,
    Mavlink,
    Motor
)
from saci.modeling.state import GlobalState

class MavlinkDisarmCPV(CPV):
    NAME = "The Mavlink Disram  Attack via Wifi"

    def __init__(self):
        super().__init__(
            
            required_components=[                
                Wifi(), # This is the entry component (Required)
                Mavlink(), # Mavlink is a required vulnerable component (Required)
                Controller(), # This is the controller hosting the firmware (Required)
                # PWMChannel(), # Removed since the PWMChannel is just a passthrough for the CPV (Not Required)
                # ESC(), # Removed since the ESC is just a passthrough for the CPV (Not Required)
                Motor(), # This is the exit component + Changed to Motor() for generalization (Required)
            ],
            
            entry_component=Wifi(),
            exit_component=Motor(),
            
            vulnerabilities=[LackWifiAuthenticationVuln(), MavlinkMitmVuln()],
            
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any (>0)",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "Moving",
                "Operating mode": "Mission or Manual",
            },
            
            attack_requirements=[
                "Computer",
                "namp",
                "mavproxy",
            ],
            
            attack_vectors=[
                BaseAttackVector(
                    name="MavLink Packets Injection",
                    signal=PacketAttackSignal(src=ExternalInput(), dst=Mavlink()),
                    required_access_level="Proximity",
                    configuration={
                        "protocol": "UDP",
                        "port": "14550",
                        "command": "disarm",
                    },
                )
            ],
            
            attack_impacts=[
                BaseAttackImpact(
                    category="Denial of Service",
                    description="The CPS crashes into the ground",
                )
            ],
            
            exploit_steps=[
                "TA1 Exploit Steps",
                    "Reverse-engineer the CPS firmware to determine if it implements security mechanisms such as MAVLink encryption or authentication.",
                    "Identify if the firmware has failsafe mechanisms to prevent unauthorized disarm commands.",
                    "Analyze the CPS control logic to assess how receiving an unauthorized disarm command affects the drone’s operation.",
                    "Create models for the following components: Ground control station, Wifi, CPS control logic, ESC logic and output, CPS actuators (e.g., motors) controlled by the ESC.",
                    "Report to TA2 any required physical parameters to simulate the CPS dynamics",
                "TA2 Exploit Steps",
                    "Implement a simulation of the ARP poisoning attack to establish a Man-In-The-Middle (MITM) position between the ground control station (GCS) and the drone.",
                    "Simulate the impact of sending a malicious MAVLink disarm command to the drone.",
                    "Collaborate with TA1 to determine the severity of the attack and possible escalation paths.",
                    "Report the findings to TA3 to conduct the experiments on the physical CPS device",
                "TA3 Exploit Steps",
                    "Use imaging tools and other techniques to catalog all Wi-Fi-related hardware components on the drone.",
                    "Identify physical interfaces that allow firmware extraction from the drone's flight controller.",
                    "Identify the specific MAVLink version used and whether encryption/authentication is enabled.",
                    "Join the drone’s open Wi-Fi network.",
                    "Set up ARP poisoning to become a MITM between the ground control station (GCS) and the drone.",
                    "Capture MAVLink messages exchanged between the GCS and the drone.",
                    "Modify and inject a malicious MAVLink disarm command into the communication channel.",
                    "Observe that the drone disarms and verify that the ground control station loses control over it.",
                    "Log network traffic and MAVLink messages before, during, and after the attack.",
                    "Analyze the CPS’s physical response to the disarm command using telemetry and external tracking.",
            ],
            
            associated_files=[],
            # TODO: add a video link!
            reference_urls=[
                "https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8425627&tag=1",
                "Add a video link",
            ],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
