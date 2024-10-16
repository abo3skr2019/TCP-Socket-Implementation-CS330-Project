class Checksum:
    @staticmethod
    def calculate(data):
        """
        Calculate the checksum for the given data.
        The checksum is used to verify data integrity.
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

    @staticmethod
    def validate(data, received_checksum):
        """
        Validate the checksum for the given data.
        """
        return Checksum.calculate(data) == received_checksum
