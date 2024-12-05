from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import Telemetry, Controller, ControllerHigh, MultiCopterMotor, MultiCopterMotorAlgo, SikRadio, Mavlink, ESC
from saci.modeling.state import GlobalState

from saci_db.vulns.mavlink_mitm_vuln import MavlinkVuln01
from saci_db.vulns.sik_vuln import SiKAuthVuln01

from saci_db.devices.px4_quadcopter_device import PX4Controller

class MavlinkCPV(CPV):

    NAME = "The Mavlink CPV"

    sik_auth_vuln = SiKAuthVuln01()
    mavlink_vuln = MavlinkVuln01()

    def __init__(self):
        super().__init__(
            required_components=[
                SikRadio(),
                Mavlink(),
                PX4Controller(),
                ESC(),
                MultiCopterMotor(),
            ],
        
        # TODO: how to describe what kind of input is needed
        entry_component = SikRadio(),
        exit_component = MultiCopterMotor(),

        vulnerabilities=[self.sik_auth_vuln, self.mavlink_vuln],

        initial_conditions = [],
        attack_requirements = [],

        attack_vectors = [],

        attack_impacts = [],

        exploit_steps = [],

        associated_files=[],

        reference_urls=["add alink the video we have"],
        )

        # We want the motor to be powered, but to be doing nothing. This can be described as neither
        # having lift, pitch, or yaw.

        gms = MultiCopterMotorAlgo()
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
            elif isinstance(component, Telemetry) and not component.powered:
                return False
            elif isinstance(component, ControllerHigh) and not component.powered:
                return False
        return True
