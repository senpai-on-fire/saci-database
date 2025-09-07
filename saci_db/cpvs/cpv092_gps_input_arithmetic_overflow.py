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


class GPSInputArithmeticOverflow(CPV):
    NAME = "GPS Input Arithmetic Overflow"

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
                            "param set GPS_TYPE 14",
                            "reboot",
                            "watch GPS_RAW_INT",
                        ],
                    },
                )
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Loss of Control",
                    description="The CPS will experience a loss of control due to flight controller failure",
                )
            ],
            exploit_steps=[
                "TA1 Exploit Steps",
                "Extract the controller firmware using the EXPLODE tool",
                "Analyze the firmware to check for the parameters",
                
                "TA2 Exploit Steps",
                "Setup software-in-the-loop simulation environment",
                "Simulate in the simulation environment to validate the attack",
                "Assess the impact of the attack based on simulation results",
                "Report findings to TA3 for physical CPS device experimentation",

                "TA3 Exploit Steps",
                "Turn on controller and drone system",
                "Launch MAVProxy with command: mavproxy.py --master=udp:0.0.0.0:14555 --console",
                "Disable drone safety (press black button for 2 seconds)",
                "Arm drone (hold rudder bottom right)",
                "Switch to 'Stabilize' mode",
                "Run the commands in MAVProxy console",
                "Execute the script that sends GPS input through MAVProxy (gps_input_attack.py)",
                "Observe effect on the controller through MAVProxy console",
                "Disarm drone (hold rudder bottom left)",
                "Document all system responses and behaviors",
            ],
            associated_files=["gps_input_attack.py"],
            reference_urls=[],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO
        pass
