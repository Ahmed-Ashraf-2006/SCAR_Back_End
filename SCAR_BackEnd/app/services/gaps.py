from sqlalchemy import func
from sqlalchemy.orm import Session

from app.schemas import GapInfo


def find_gap(db: Session, sequence_column, filters: list, sequence: int) -> GapInfo | None:
    """Compare a new sequence number with the highest one already stored for the same stream.

    A jump of more than 1 means packets were lost on the way. Out-of-order (older) packets are not
    reported as gaps. Exact repeats are rejected earlier as duplicates.
    """
    previous = db.query(func.max(sequence_column)).filter(*filters).scalar()
    if previous is not None and sequence > previous + 1:
        return GapInfo(expected_sequence=previous + 1, received_sequence=sequence, missing=sequence - previous - 1)
    return None
