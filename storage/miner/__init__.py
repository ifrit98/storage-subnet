from . import config
from . import utils
from .run import run
from .set_weights import set_weights
from .priority import priority, default_priority


__version__ = "0.0.1"
version_split = __version__.split(".")
__spec_version__ = (
    (1000 * int(version_split[0]))
    + (10 * int(version_split[1]))
    + (1 * int(version_split[2]))
)
