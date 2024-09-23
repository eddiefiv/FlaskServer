from dataclasses import dataclass, asdict

@dataclass
class User(object):
    """Represents a User within the Psql database

    Attributes
    ----------
    id (int)
        The user's id
    email (str)
        The user's email
    username (str)
        The user's username
    permissions (list[str])
        A list of the user's authorized permissions
    verified (bool)
        The verification status of the user"""
    id: int
    email: str
    username: str
    permissions: list[str]
    verified: bool

    def dict(self) -> dict[str, any]:
        return {k: v for k, v in asdict(self).items()}