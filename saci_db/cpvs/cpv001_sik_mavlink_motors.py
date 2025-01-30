from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import GCS, TelemetryHigh, Controller, MultiCopterMotor, MultiCopterMotorAlgo, PWMChannel, SikRadio, Mavlink, ESC
from saci.modeling.state import GlobalState

from saci_db.vulns.mavlink_mitm_vuln import MavlinkMitmVuln
from saci_db.vulns.sik_flooding_vuln import SiKFloodingVuln

from saci_db.devices.px4_quadcopter_device import PX4Controller

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
            elif isinstance(component, TelemetryHigh) and not component.powered:
                return False
            elif isinstance(component, Controller) and not component.powered:
                return False
        return True
