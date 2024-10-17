def calculate_checksum(data):
   """
    Calculate the checksum for the given data.
    This helps ensure the data hasn't been corrupted.

    Parameters:
    data (bytes): The data you want to check.

    Returns:
    int: The calculated checksum.
    """
    checksum = 0
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            word = (data[i] << 8) + data[i + 1]
        else:
            word = data[i] << 8
        checksum += word
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return ~checksum & 0xFFFF

def validate_checksum(data, received_checksum):
   """
    Check if the checksum for the given data is correct.

    Parameters:
    data (bytes): The data you want to validate.
    received_checksum (int): The checksum that came with the data.

    Returns:
    bool: True if the checksum is correct, False otherwise.
    """
    return calculate_checksum(data) == received_checksum