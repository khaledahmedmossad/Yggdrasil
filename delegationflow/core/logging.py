import logging


class SecretRedactionFilter(logging.Filter):
    """Basic defense against accidentally logging common credential fields."""
    SENSITIVE = ("password", "passwd", "nt_hash", "lm_hash", "ticket", "secret")

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        lowered = message.lower()
        if any(token in lowered for token in self.SENSITIVE):
            record.msg = "[REDACTED: potentially sensitive log message]"
            record.args = ()
        return True


def configure_logging(verbose: bool = False) -> None:
    handler = logging.StreamHandler()
    handler.addFilter(SecretRedactionFilter())
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
        handlers=[handler],
        force=True,
    )
