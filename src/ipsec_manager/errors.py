class ManagerError(Exception):
    def __init__(self, status: str, message: str):
        super().__init__(message)
        self.status = status


EXIT_CODES = {
    "success": 0,
    "already_covered": 0,
    "not_found": 3,
    "conflict": 4,
    "invalid_input": 2,
    "unsupported": 5,
    "permission_denied": 6,
    "backup_failed": 7,
    "verification_failed": 8,
    "indeterminate": 9,
}
