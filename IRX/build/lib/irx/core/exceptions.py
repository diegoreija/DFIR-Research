"""Expected application errors and their CLI exit codes."""


class IRXError(Exception):
    exit_code = 1


class ConfigurationError(IRXError):
    exit_code = 2


class NotFoundError(IRXError):
    exit_code = 3


class IntegrityError(IRXError):
    exit_code = 4


class ConflictError(IRXError):
    exit_code = 5


class PermissionError(IRXError):
    exit_code = 6
