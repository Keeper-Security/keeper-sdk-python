import dataclasses
from typing import Optional, Generic, get_args

from keepercli.commands import base


@dataclasses.dataclass
class Context:
    sss: Optional[str] = None


c = Context()

def get_context():
    return c
a = base.GetterSetterCommand('sss', 'SSS', get_context)
a.execute_args('ffff')
pass