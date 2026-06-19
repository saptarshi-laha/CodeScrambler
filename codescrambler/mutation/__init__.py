"""The standalone mutation engine.

Import the individual passes, or the convenience :class:`Mutator`, or call
:func:`build_passes` to get the default intensity-scaled pipeline. None of this
imports the virtualization or protection engines, so the mutation engine can be
used on its own in another project.
"""

from codescrambler.mutation.antidisasm import AntiDisasmPass
from codescrambler.mutation.base import Pass, PassReport, register
from codescrambler.mutation.branchfunc import BranchFunctionPass
from codescrambler.mutation.callswitch import CallSwitchPass
from codescrambler.mutation.constants import ConstantUnfoldPass
from codescrambler.mutation.junk import JunkPass
from codescrambler.mutation.jumps import JumpPass
from codescrambler.mutation.mba import MBAPass
from codescrambler.mutation.mutator import Mutator, build_passes
from codescrambler.mutation.opaque import OpaquePass
from codescrambler.mutation.reorder import ReorderPass
from codescrambler.mutation.scatter import BlockScatterPass
from codescrambler.mutation.stacknoise import StackNoisePass
from codescrambler.mutation.substitute import SubstitutePass

__all__ = [
    "Pass", "PassReport", "register",
    "Mutator", "build_passes",
    "JunkPass", "OpaquePass", "SubstitutePass", "JumpPass", "CallSwitchPass",
    "MBAPass", "ConstantUnfoldPass", "ReorderPass", "StackNoisePass", "AntiDisasmPass",
    "BlockScatterPass", "BranchFunctionPass",
]
