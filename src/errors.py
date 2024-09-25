class UserRetrievalException(Exception):
    """Raised when an error occurs during user retrieval"""
    ...

class UserCreationException(Exception):
    """Raised when an error occurs during user creation"""
    ...

class UserVerificationException(Exception):
    """Raised when an error occurs during user verification"""
    ...

class UserPermissionAppendException(Exception):
    """Raised when an error occurs during the appending of user permissions"""
    ...

class OrderPlaceException(Exception):
    """Raised when an error occurs during order placement"""
    ...

class OrderRetrievalException(Exception):
    """Raised when an error occurs during order retrieval"""
    ...

class ItemRetrievalException(Exception):
    """Raised when an error occurs during item retrieval"""
    ...

class ItemCreationException(Exception):
    """Raised when an error occurs during item creation"""
    ...