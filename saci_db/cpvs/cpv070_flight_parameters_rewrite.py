from saci.modeling import CPV

from saci_db.vulns.wifi_knowncreds_vuln import WifiKnownCredsVuln
from ..vulns.mavlink_mitm_vuln import MavlinkMitmVuln

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

class FlightParametersRewriteCPV(CPV):
    NAME = "Flight Parameter Rewrite via MAVLink"

    def __init__(self):
        super().__init__(
            
            required_components=[
                Wifi(), # This is the entry component (Required)
                Mavlink(), # This is a vulnerable required component (Required)
                Controller(), # Changed from PX4Controller() to Controller() for generalization (Required)
                # PWMChannel(), # Removed since the PWMChannel is just a passthrough for the CPV (Not Required)
                # ESC(), # Removed since the ESC is just a passthrough for the CPV (Not Required)
                Motor(), # This is the exit component + Changed to Motor() for generalization (Required)
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
                    signal=PacketAttackSignal(
                        src=Wifi(), dst=Controller()
                    ),  
                    required_access_level="Proximity",
                    configuration={
                        "protocol": "UDP",
                        "port": "14555",
                        "command": "param set",
                    },
                )
            ],
            
            attack_impacts=[
                BaseAttackImpact(
                    category="Loss of Control",
                    description="The CPS will experience a loss in stability",
                )
            ],
            
            exploit_steps=[
                "TA1 Exploit Steps",
                    "Reverse-engineer the CPS firmware to determine if it implements security mechanisms such as MAVLink encryption or authentication.",
                    "Identify if the firmware has failsafe mechanisms to prevent unauthorized parameter set commands.",
                    "Analyze the CPS control logic to assess how receiving an unauthorized parameter set command affects the drone’s operation.",
                    "Create models for the following components: Ground control station, Wifi, CPS control logic, ESC logic and output, CPS actuators (e.g., motors) controlled by the ESC.",
                    "Report to TA2 any required physical parameters to simulate the CPS dynamics",
                "TA2 Exploit Steps",
                    "Implement a simulation of the ARP poisoning attack to establish a Man-In-The-Middle (MITM) position between the ground control station (GCS) and the drone.",
                    "Simulate the impact of sending a malicious MAVLink parameter set command to the drone.",
                    "Collaborate with TA1 to determine the severity of the attack and possible escalation paths.",
                    "Report the findings to TA3 to conduct the experiments on the physical CPS device",
                "TA3 Exploit Steps",
                    "Turn on controller and drone system",
                    "Connect attacker system to ExpressLRS Wi-Fi (password: expresslrs)",
                    "Launch MAVProxy with command: mavproxy.py --master=udp:0.0.0.0:14555 --console",
                    "Record original INS_GYROFFS_X parameter value using 'param fetch INS_GYROFFS_X'",
                    "Disable drone safety (press black button for 2 seconds)",
                    "Arm drone (hold rudder bottom right)",
                    "Switch to 'Stabilize' mode using shoulder switch",
                    "Set throttle to mid-position and verify steady motor speed",
                    "Execute attack by setting 'param set INS_GYROFFS_X 10'",
                    "Verify the oscillation of the motor speed after issuing the command",
                    "Restore original INS_GYROFFS_X value",
                    "Return throttle to bottom position",
                    "Disarm drone (hold rudder bottom left)",
                    "Retry the experiment for the following parameters: COMPASS_DIA_X / COMPASS_DIA_Y / COMPASS_DIA_Z / COMPASS_DIA2_X / COMPASS_DIA2_Y / COMPASS_DIA2_Z COMPASS_DIA3_X / COMPASS_DIA3_Y / COMPASS_DIA3_Z / COMPASS_ODI2_X / COMPASS_ODI2_Y / COMPASS_ODI2_Z / COMPASS_ODI3_X / COMPASS_ODI3_Y / COMPASS_ODI3_Z / COMPASS_ODI_X / COMPASS_ODI_Y / COMPASS_ODI_Z / GPS_POS1_X / GPS_POS1_Y / GPS_POS1_Z / INS_ACC2OFFS_X / INS_ACC2OFFS_Y / INS_ACC2OFFS_Z / INS_ACC2SCAL_X / INS_ACC2SCAL_Y / INS_ACC2SCAL_Z / INS_ACCOFFS_X / INS_ACCOFFS_Y / INS_ACCOFFS_Z / INS_ACCSCAL_X / INS_ACCSCAL_Y / INS_ACCSCAL_X Z / INS_GYR2OFFS_X / INS_GYR2OFFS_Y / INS_GYR2OFFS_Z / INS_GYROFFS_X / INS_GYROFFS_Y / INS_GYROFFS_Z / INS_POS1_X / INS_POS1_Y / INS_POS1_Z RC3_MAX / RC3_MIN / ANGLE_MAX",
                    "Document all system responses and behaviors",
            ],
            
            associated_files=[],
            reference_urls=[
                "https://github.com/senpai-on-fire/owlet-taskboard/blob/main/CPVs/IVV_Feedback/PASS/HII-GS0409380007-CPV004-20250303.docx"
            ],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO
        pass
