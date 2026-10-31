"""DA-ROV policy adapter for the pinned BGPy engine.

The routing engine remains unmodified.  This adapter delegates all DA policy
semantics to the executable Phase 4 oracle and changes only BGPy's inbound
route-admission decision.
"""

from __future__ import annotations

from typing import ClassVar

from bgpy.shared.enums import Relationships
from bgpy.simulation_engine import Announcement, BGP, ROV

from phase4_encoding.scripts.utils.daroa import DAROA, ValidationState


class DAROV(ROV):
    """BGPy policy that composes DA-ROV with conventional ROV.

    ``Explicit`` and ``Delegated`` are admitted, ``Invalid`` is rejected, and
    ``NotFound`` falls back to BGPy's native conventional ROV check.  The
    configured :class:`DAROA` is immutable during one simulation run.
    """

    name = "DA-ROV Phase 7"
    _daroa: ClassVar[DAROA | None] = None

    @classmethod
    def configure(cls, daroa: DAROA) -> None:
        """Install the signed-policy semantic oracle for the next run."""

        if not isinstance(daroa, DAROA):
            raise TypeError(f"expected DAROA, got {type(daroa).__name__}")
        cls._daroa = daroa

    @classmethod
    def validation_state(cls, prefix: str, origin_asn: int) -> ValidationState:
        """Return the Phase 4 oracle state for a route."""

        if cls._daroa is None:
            raise RuntimeError("DAROV.configure() must be called before simulation")
        return cls._daroa.validate_route(prefix, origin_asn)

    def _valid_ann(
        self,
        ann: Announcement,
        recv_rel: Relationships,
    ) -> bool:
        """Apply the DA state/action composition before ordinary BGP checks."""

        state = self.validation_state(ann.prefix, ann.origin)
        if state in (ValidationState.EXPLICIT, ValidationState.DELEGATED):
            # Authorized by the DA object, but still enforce loop prevention.
            return BGP._valid_ann(self, ann, recv_rel)
        if state == ValidationState.INVALID:
            return False
        if state == ValidationState.NOT_FOUND:
            # Unrelated routes retain native ROV semantics.
            return ROV._valid_ann(self, ann, recv_rel)
        raise AssertionError(f"unhandled DA validation state: {state}")
