from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import GCS, TelemetryHigh, Controller, MultiCopterMotor, MultiCopterMotorAlgorithmic, PWMChannel, SikRadio, Mavlink, ESC
from saci.modeling.state import GlobalState

from saci_db.vulns.mavlink_mitm_vuln import MavlinkMitmVuln
from saci_db.vulns.sik_flooding_vuln import SiKFloodingVuln

from saci_db.devices.px4_quadcopter_device import PX4Controller

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.radio_attack_signal import RadioAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

class MavlinkSiKCPV(CPV):

    NAME = "The Mavlink and SiK Radio Attack"

    sik_auth_vuln = SiKFloodingVuln()
    mavlink_vuln = MavlinkMitmVuln()

    def __init__(self):
        super().__init__(
            required_components=[
                GCS(),
                SikRadio(),
                Mavlink(),
                TelemetryHigh(), 
                PX4Controller(),
                PWMChannel(), 
                ESC(),
                MultiCopterMotor(),
            ],
        
        # TODO: how to describe what kind of input is needed
        entry_component = GCS(),
        exit_component = MultiCopterMotor(),

        vulnerabilities=[self.sik_auth_vuln, self.mavlink_vuln],

        initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "None",
                "Environment": "Open Field or Urban Area",
                "RemoteController": "Active",
                "CPSController": "Active",
                # TODO: stabilization machanism when moving?
                "OperatingMode": "Manual or Mission",
            },
        attack_requirements = [
            "MAVLink packet generator/interception device",
            "Physical access to JP7 bus between receiver and flight controller"
        ],

        attack_vectors = [
            BaseAttackVector(
                name="MAVLink Command Injection",
                signal= RadioAttackSignal(
                    src=GCS(), 
                    dst=Mavlink(),
                    modality="uart_signals"
                ),
                required_access_level="Physical",
                configuration={"duration": "Immediate"}
            )
        ],

        attack_impacts = [
            BaseAttackImpact(
                category="Control Manipulation",
                description=(
                    "Motors will spin erratically on the delivered system. If the system were actually flown, "
                    "then the drone would fly in an unpredictable pattern and potentially crash."
                )
            )
        ],

        exploit_steps = [
            "Connect MAVLink packet generator between RF receiver and flight computer board at JP7",
            "Power on the drone",
            "Power on the transmitter",
            "Turn off drone safety by pressing black button for two seconds",
            "Arm the drone by holding rudder in bottom right position until motors spin",
            "Move throttle to max position",
            "MAVLink packet generator reads commands from RF receiver and generates competing commands",
            "Return throttle to bottom position",
            "Disarm drone by holding rudder in bottom left position until motors stop"
        ],


        associated_files=[],

        reference_urls=["https://github.com/senpai-on-fire/owlet-taskboard/tree/main/CPVs/HII-GS0409380007-CPV010"],
        )

        # We want the motor to be powered, but to be doing nothing. This can be described as neither
        # having lift, pitch, or yaw.

        gms = MultiCopterMotorAlgorithmic()
        gms.conditions = [
            gms.v["yaw"] == 0,
            gms.v["pitch"] == 0,
            gms.v["lift"] == 0,
        ]
        self.goal_motor_state = gms.conditions

        

    def in_goal_state(self, state: GlobalState):
        for component in state.components:
            if isinstance(component, MultiCopterMotor):
                if not component.powered:
                    return False
            elif isinstance(component, MultiCopterMotor):
                if component != self.goal_motor_state:
                    return False
            elif isinstance(component, TelemetryHigh) and not component.powered:
                return False
            elif isinstance(component, Controller) and not component.powered:
                return False
        return True
