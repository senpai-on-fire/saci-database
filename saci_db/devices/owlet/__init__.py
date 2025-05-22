"""Auto-generated device for system "owlet"."""

import os
import networkx as nx
from clorm import Predicate, IntegerField

from saci.modeling.device import Device

# TODO: dedup these imports, also check to make sure we don't have component name clashes

from saci.modeling.device.control.controller import Controller

from saci.modeling.device.control.navigation_control import NavigationControlLogic

from saci.modeling.device.control.speed_control import SpeedControlLogic

from saci.modeling.device.sik_radio import SikRadio

from .antenna1 import antenna1

from .antenna2 import antenna2

from saci.modeling.device.motor.motor import Motor

from saci.modeling.device.motor.multi_copter_motor import MultiCopterMotor

from saci.modeling.device.motor.multi_copter_motor import MultiCopterMotor

from saci.modeling.device.motor.multi_copter_motor import MultiCopterMotor

from saci.modeling.device.motor.multi_copter_motor import MultiCopterMotor

from saci.modeling.device.battery.bms import BMSHardware

from saci.modeling.device.battery.battery import Battery

from saci.modeling.device.battery.battery import Battery

from .fan import fan

from .airframe import airframe

from .dome import dome

from .frame import frame

from .batterycage import batterycage

from .buttonassembly import buttonassembly

from saci.modeling.device.telemetry import Telemetry

from saci.modeling.device.component.hardware.component_hw_circuit import HardwareCircuit

from saci.modeling.device.sik_radio import SikRadio

from saci.modeling.device.component.hardware.component_hw_circuit import HardwareCircuit

from saci.modeling.device.component.hardware.component_hw_circuit import HardwareCircuit

from saci.modeling.device.component.hardware.component_hw_circuit import HardwareCircuit

from saci.modeling.device.battery.bms import BMS

from saci.modeling.device.battery.battery import Battery

from saci.modeling.device.battery.battery import Battery


class owletCrash(Predicate):
    time = IntegerField()


class owlet(Device):
    crash_atom = owletCrash
    description = os.path.join(os.path.dirname(os.path.realpath(__file__)), "device.lp")

    def __init__(self, state=None):
        components = []

        comp_compute = Controller(name="compute")
        components.append(comp_compute)

        comp_flight_computer = NavigationControlLogic(name="flight_computer")
        components.append(comp_flight_computer)

        comp_esc = SpeedControlLogic(name="esc")
        components.append(comp_esc)

        comp_rf = SikRadio(name="rf")
        components.append(comp_rf)

        comp_antenna1 = antenna1(name="antenna1")
        components.append(comp_antenna1)

        comp_antenna2 = antenna2(name="antenna2")
        components.append(comp_antenna2)

        comp_motors = Motor(name="motors")
        components.append(comp_motors)

        comp_motor1 = MultiCopterMotor(name="motor1")
        components.append(comp_motor1)

        comp_motor2 = MultiCopterMotor(name="motor2")
        components.append(comp_motor2)

        comp_motor3 = MultiCopterMotor(name="motor3")
        components.append(comp_motor3)

        comp_motor4 = MultiCopterMotor(name="motor4")
        components.append(comp_motor4)

        comp_power = BMSHardware(name="power")
        components.append(comp_power)

        comp_battery1 = Battery(name="battery1")
        components.append(comp_battery1)

        comp_battery2 = Battery(name="battery2")
        components.append(comp_battery2)

        comp_fan = fan(name="fan")
        components.append(comp_fan)

        comp_airframe = airframe(name="airframe")
        components.append(comp_airframe)

        comp_dome = dome(name="dome")
        components.append(comp_dome)

        comp_frame = frame(name="frame")
        components.append(comp_frame)

        comp_battery_cage = batterycage(name="battery cage")
        components.append(comp_battery_cage)

        comp_button_assembly = buttonassembly(name="button_assembly")
        components.append(comp_button_assembly)

        comp_transmitter = Telemetry(name="transmitter")
        components.append(comp_transmitter)

        comp_pocket_v2 = HardwareCircuit(name="pocket_v2")
        components.append(comp_pocket_v2)

        comp_pocket_radio = SikRadio(name="pocket_radio")
        components.append(comp_pocket_radio)

        comp_pocket_con = HardwareCircuit(name="pocket_con")
        components.append(comp_pocket_con)

        comp_pocket_switch_e = HardwareCircuit(name="pocket_switch_e")
        components.append(comp_pocket_switch_e)

        comp_pocket_pot = HardwareCircuit(name="pocket_pot")
        components.append(comp_pocket_pot)

        comp_pocket_power = BMS(name="pocket_power")
        components.append(comp_pocket_power)

        comp_pocket_battery1 = Battery(name="pocket_battery1")
        components.append(comp_pocket_battery1)

        comp_pocket_battery2 = Battery(name="pocket_battery2")
        components.append(comp_pocket_battery2)

        component_graph = nx.from_edgelist(
            [
                (comp_rf, comp_antenna1),
                (comp_rf, comp_antenna2),
                (comp_antenna1, comp_rf),
                (comp_antenna2, comp_rf),
                (comp_flight_computer, comp_rf),
                (comp_flight_computer, comp_esc),
                (comp_esc, comp_flight_computer),
                (comp_rf, comp_flight_computer),
                (comp_flight_computer, comp_fan),
                (comp_flight_computer, comp_button_assembly),
                (comp_flight_computer, comp_button_assembly),
                (comp_flight_computer, comp_button_assembly),
                (comp_esc, comp_motor2),
                (comp_esc, comp_battery2),
                (comp_esc, comp_motor1),
                (comp_esc, comp_motor4),
                (comp_esc, comp_motor3),
                (comp_esc, comp_battery1),
                (comp_battery1, comp_esc),
                (comp_battery1, comp_esc),
                (comp_battery1, comp_esc),
                (comp_battery2, comp_esc),
                (comp_battery2, comp_esc),
                (comp_battery2, comp_esc),
                (comp_compute, comp_flight_computer),
                (comp_compute, comp_esc),
                (comp_compute, comp_rf),
                (comp_rf, comp_antenna1),
                (comp_rf, comp_antenna2),
                (comp_motors, comp_motor1),
                (comp_motors, comp_motor2),
                (comp_motors, comp_motor3),
                (comp_motors, comp_motor4),
                (comp_power, comp_battery1),
                (comp_power, comp_battery2),
                (comp_airframe, comp_dome),
                (comp_airframe, comp_frame),
                (comp_airframe, comp_battery_cage),
                (comp_airframe, comp_button_assembly),
                (comp_transmitter, comp_pocket_v2),
                (comp_transmitter, comp_pocket_radio),
                (comp_transmitter, comp_pocket_con),
                (comp_transmitter, comp_pocket_switch_e),
                (comp_transmitter, comp_pocket_pot),
                (comp_transmitter, comp_pocket_power),
                (comp_pocket_power, comp_pocket_battery1),
                (comp_pocket_power, comp_pocket_battery2),
            ],
            create_using=nx.DiGraph,
        )

        super().__init__(
            name="owlet",
            components=components,
            component_graph=component_graph,
            state=state,
        )
