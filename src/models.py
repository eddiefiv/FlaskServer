import datetime

from dataclasses import dataclass, asdict
from collections.abc import Iterable

type OrderAlias = Order

@dataclass
class Model(object):
    """Base dataclass for all models"""
    def dict(self) -> dict[str, any]:
        return {k: v for k, v in asdict(self).items()}

@dataclass
class User(Model):
    """Represents a User within the database

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
    permissions: Iterable[str]
    verified: bool
    orders: Iterable[OrderAlias]

@dataclass
class Item(Model):
    """Represents an Item within the database

    Attributes
    ----------
    item_id (int)
        The item's id in the database
    item_categories (list[str])
        A list of the item's categories
    item_name (str)
        The public name of the item
    item_market_price (float)
        The price of the item"""
    item_id: int
    item_categories: Iterable[str]
    item_name: str
    item_market_price: float

@dataclass
class Order(Model):
    """Represents an Order structure within the database

    Attributes
    ----------
    order_id (int)
        The id of the order. For tracking or status chekcs
    ordered_on (datetime.datetime)
        The timestamp of when the order was placed
    shipping_on (datetime.datetime)
        The timestamp of when the order is set to ship
    user_id (int)
        The id of the user associated with this order
    items (list[Item])
        A list of the ordered item's"""
    order_id: int
    ordered_on: datetime.datetime
    shipping_on: datetime.datetime
    user_id: int
    items: Iterable[Item]