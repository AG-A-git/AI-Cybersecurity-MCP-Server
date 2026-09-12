def success_response(message, data=None):
    """
    Create a consistent successful API response.
    """

    return {
        "success": True,
        "message": message,
        "data": data
    }


def error_response(message):
    """
    Create a consistent error response.
    """

    return {
        "success": False,
        "message": message
    }