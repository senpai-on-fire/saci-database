from .ngcrover import NGCRover
from .px4_quadcopter_device import PX4Quadcopter
from .ardupilot_quadcopter_device import ArduPilotQuadcopter
from .propriety_quadcopter_device import ProprietyQuadcopter
from .gs_quadcopter import GSQuadcopter
from .owlet import owlet
# from .px4_fixedwing_device import PX4FixedWingDrone

devices = {
    "ngcrover": NGCRover(),
    "px4quadcopter": PX4Quadcopter(),
    "gsquadcopter": GSQuadcopter(),
    "arduquadcopter": ArduPilotQuadcopter(),
    "privatequadcopter": ProprietyQuadcopter(),
    "owlet": owlet(),
    # "px4fixedwingdrone": PX4FixedWingDrone(),
}
