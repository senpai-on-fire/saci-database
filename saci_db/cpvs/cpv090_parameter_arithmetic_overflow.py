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


class ParameterArithmeticOverflowCPV(CPV):
    NAME = "Parameter Arithmetic Overflow via MAVLink"

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
                        "command": "param set",
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
                "Record original COMPASS_DIA_X parameter value using 'param fetch COMPASS_DIA_X'",
                "Disable drone safety (press black button for 2 seconds)",
                "Arm drone (hold rudder bottom right)",
                "Switch to 'Stabilize' mode",
                "Execute attack by settingt the parameter to a big value, e.g. 'param set COMPASS_DIA_X 100000000000000'",
                "Observe effect on the controller through MAVProxy console",
                "Restore original COMPASS_DIA_X value",
                "Disarm drone (hold rudder bottom left)",
                "Retry the experiment for the following parameters: COMPASS_DIA_Y / COMPASS_DIA_Z / COMPASS_DIA2_X / COMPASS_DIA2_Y / COMPASS_DIA3_X / COMPASS_DIA3_Y / COMPASS_ODI2_X / COMPASS_ODI2_Y / COMPASS_ODI2_Z / COMPASS_ODI3_X / COMPASS_ODI3_Y / COMPASS_ODI3_Z / COMPASS_ODI_X / COMPASS_ODI_Y / COMPASS_ODI_Z / GPS_POS1_X / GPS_POS1_Y / INS_ACC2OFFS_X / INS_ACC2OFFS_Y / INS_ACC2SCAL_X / INS_ACC2SCAL_Y / INS_ACCOFFS_X / INS_ACCOFFS_Y / INS_ACCOFFS_Z / INS_ACCSCAL_Z / INS_GYR2OFFS_X / INS_GYR2OFFS_Y / INS_GYR2OFFS_Z / INS_GYROFFS_X / INS_GYROFFS_Y / INS_GYROFFS_Z / INS_POS1_X / INS_POS1_Y / INS_POS1_Z / RC3_MIN / AHRS_TRIM_Z / BATT_AMP_OFFSET / BATT_VOLT_MULT / COMPASS_DIA2_Z / COMPASS_DIA3_Z / SERIAL0_BAUD / SERIAL1_BAUD / SERIAL2_BAUD / SERIAL3_BAUD / SERIAL4_BAUD / SERIAL5_BAUD / SERIAL6_BAUD / SERIAL7_BAUD / STAT_FLTTIME / ARMING_MIS_ITEMS / LOG_BITMASK / DEV_OPTIONS / RTL_LOIT_TIME / STAT_RUNTIME / STAT_RESET / ARMING_CHECK / FS_OPTIONS / INS_ACCSCAL_X / INS_ACCSCAL_Y / INS_POS2_X / INS_POS2_Y / INS_POS2_Z / COMPASS_DEV_ID2 / COMPASS_OFS3_X / COMPASS_OFS3_Y / COMPASS_OFS3_Z / COMPASS_OFS_X / COMPASS_OFS_Y / COMPASS_OFS_Z / COMPASS_OFS2_X / COMPASS_OFS2_Y / COMPASS_OFS2_Z / BRD_OPTIONS / AHRS_TRIM_X / AHRS_TRIM_Y / COMPASS_TYPEMASK / INS_ACC2SCAL_Z / INS_ACC2OFFS_Z / SERVO_ROB_POSMIN / GPS_POS1_Z / BATT_CAPACITY / RC_OPTIONS / INS_ACC_ID / INS_ACC2_ID / BATT_ARM_MAH / SERVO_VOLZ_MASK / INS_GYR_ID / ANGLE_MAX / ALT_HOLD / BATT_SERIAL_NUM / SERVO_ROB_POSMAX / SIM_OPOS_LNG / SIM_WIND_T_ALT",
                "Document all system responses and behaviors",
            ],
            associated_files=[],
            reference_urls=[
                "https://discuss.ardupilot.org/t/setting-excessively-large-parameter-values-causes-arithmetic-overflow/127633"
            ],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO
        pass
