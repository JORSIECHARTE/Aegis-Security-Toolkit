import logging

from config import APP_NAME


LOGGER_NAME = "aegis"
LOG_FORMAT = (
    "%(asctime)s | %(levelname)s | "
    "%(name)s | %(message)s"
)
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def configure_logging():
    logger = logging.getLogger(LOGGER_NAME)

    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    formatter = logging.Formatter(
        fmt=LOG_FORMAT,
        datefmt=DATE_FORMAT,
    )

    console_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.propagate = False

    logger.info(
        "%s logging initialized.",
        APP_NAME,
    )

    return logger


def get_logger(module_name=None):
    if module_name:
        return logging.getLogger(
            f"{LOGGER_NAME}.{module_name}"
        )

    return logging.getLogger(LOGGER_NAME)