"""S2-ROV policy adapter for the pinned BGPy engine.

The routing engine remains unmodified.  This adapter delegates all S2-ROV policy
semantics to the executable S2-ROV-encoding oracle and changes only BGPy's inbound
route-admission decision.
"""

from __future__ import annotations

from typing import ClassVar

from bgpy.shared.enums import Relationships
from bgpy.simulation_engine import Announcement, BGP, ROV

from implementation.s2rov_codec.scripts.utils.s2rov import S2ROV, ValidationState


class S2ROV(ROV):
    """BGPy policy that composes S2-ROV with conventional ROV.

    ``Explicit`` and ``Delegated`` are admitted, ``Invalid`` is rejected, and
    ``NotFound`` falls back to BGPy's native conventional ROV check.  The
    configured :class:`S2ROV` is immutable during one simulation run.
    """

    name = "S2-ROV routing-model"
    _s2rov: ClassVar[S2-ROV | None] = None

    @classmethod
    def configure(cls, s2rov: S2ROV) -> None:
        """Install the signed-policy semantic oracle for the next run."""

        if not isinstance(s2rov, S2ROV):
            raise TypeError(f"expected S2ROV, got {type(s2rov).__name__}")
        cls._s2rov = s2rov

    @classmethod
    def validation_state(cls, prefix: str, origin_asn: int) -> ValidationState:
        """Return the S2-ROV-encoding oracle state for a route."""

        if cls._s2rov is None:
            raise RuntimeError("S2ROV.configure() must be called before simulation")
        return cls._s2rov.validate_route(prefix, origin_asn)

    def _valid_ann(
        self,
        ann: Announcement,
        recv_rel: Relationships,
    ) -> bool:
        """Apply the S2-ROV state/action composition before ordinary BGP checks."""

        state = self.validation_state(ann.prefix, ann.origin)
        if state in (ValidationState.EXPLICIT, ValidationState.DELEGATED):
            # Authorized by the S2-ROV object, but still enforce loop prevention.
            return BGP._valid_ann(self, ann, recv_rel)
        if state == ValidationState.INVALID:
            return False
        if state == ValidationState.NOT_FOUND:
            # Unrelated routes retain native ROV semantics.
            return ROV._valid_ann(self, ann, recv_rel)
        raise AssertionError(f"unhandled S2-ROV validation state: {state}")
