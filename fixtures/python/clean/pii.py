import logging
logger = logging.getLogger(__name__)

def signup(user_id: str) -> None:
    logger.info("signup %s", user_id)
