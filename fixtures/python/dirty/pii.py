import logging
logger = logging.getLogger(__name__)

def signup(email: str) -> None:
    logger.info(email)
