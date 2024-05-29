from saci.modeling.device import ControllerHigh, Controller


class PX4Controller(Controller):
    def __init__(self):
        super().__init__(name="PX4 Controller")
