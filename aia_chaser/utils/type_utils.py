import enum
import sys


if sys.version_info >= (3, 11):
    StrEnum = enum.StrEnum
else:

    class StrEnum(str, enum.Enum):
        """Enum subclass to define string constants that behave like str.

        Additionally it also redefines __str__ to return the value instead of
        showing a string that also includes the Enum's part.
        """

        def __str__(self) -> str:
            """String representation of the str-based enum object.

            Returns:
                The value of the enum object, which is already an str.
            """
            return self.value
