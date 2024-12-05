from saci.modeling.device import ControllerHigh, Controller


class PX4Controller(Controller):
    def __init__(self):
        super().__init__()
