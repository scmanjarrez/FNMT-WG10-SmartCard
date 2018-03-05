import sys
from math import ceil

from Crypto.Cipher import DES, DES3

dbg = False
iv = "0000000000000000"
byte_block_size = 8
hex_block_size = 16
admkey = None
sk = None


def byte_to_hex(byteStr):
    """Converts a byte string format into hex string format

    Args:
        byteStr:  Byte string, \xff\x0a...

    Returns:
        The conversion of byteStr in hex string format, FF0A...
    """
    # https://code.activestate.com/recipes/510399-byte-to-hex-and-hex-to-byte-string-conversion/

    return ''.join(["%02X" % ord(x) for x in byteStr])


def hex_to_byte(hexStr):
    """Converts a hex string format into byte string format

    Args:
        hexStr:  Hex string, FF0A...

    Returns:
        The conversion of hexStr in byte string format, \xff\x0a...
    """
    # https://code.activestate.com/recipes/510399-byte-to-hex-and-hex-to-byte-string-conversion/

    byte = []
    hexStr = ''.join(hexStr.split(" "))
    for i in range(0, len(hexStr), 2):
        byte.append(chr(int(hexStr[i:i+2], 16)))

    return ''.join(byte)


def encrypt_des(key8B, data):
    """Encrypts data with DES (CBC, 0) using key8B

    Args:
        key8B: key (8B) to be used, hex string format
        data: data to be encrypted, byte string format

    Returns:
        The encryption of data, in byte string format
    """

    key = hex_to_byte(key8B)
    cipher = DES.new(key, DES.MODE_CBC, hex_to_byte(iv))

    return cipher.encrypt(data)


def encrypt_3des(key16B, data):
    """Encrypts data with 3DES (CBC, 0) using key16B

    Args:
        key16B: key (16B) to be used, hex string format
        data: data to be encrypted, byte string format

    Returns:
        The encryption of data, in byte string format
    """

    key = hex_to_byte(key16B)
    cipher = DES3.new(key, DES3.MODE_CBC, hex_to_byte(iv))

    return cipher.encrypt(data)


def do_xor(data1, data2):
    """Calculates XOR of data1 and data2

    Args:
        data1: first block to be used, hex string format
        data2: second block to be used, byte string format

    Returns:
        The XOR of data1 with data2, in byte format
    """

    return ''.join([chr(ord(b1) ^ ord(b2))
                    for (b1, b2) in zip(hex_to_byte(data1), data2)])


def calculate_last_block(blocks, sk):
    """Calculates the last block to check if data is correctly encrypted

    Args:
        blocks: list of blocks, in hex string
        sk: session key to be used, in hex string format

    Returns:
        The last block after chaining DES, XOR and last block with 3DES
    """

    last_block = hex_to_byte(iv)
    sk1 = sk[:16]
    for i, block in enumerate(blocks):
        xor = do_xor(block, last_block)
        if dbg:
            print("Current block: {} Last Block: {}"
                  .format(block, byte_to_hex(last_block)))
            print("XOR: {}"
                  .format(byte_to_hex(xor)))

        if i == len(blocks)-1:
            last_block = encrypt_3des(sk, xor)
            if dbg:
                print("3DES: {}"
                      .format(byte_to_hex(last_block)))
        else:
            last_block = encrypt_des(sk1, xor)
            if dbg:
                print("DES: {}"
                      .format(byte_to_hex(last_block)))

    return last_block


def calculate_cryptogram(blocks, sk):
    """Calculates the cryptogram of data

    Args:
        blocks: list of blocks, in hex string
        sk: session key to be used, in hex string format

    Returns:
        The last block after chaining DES, XOR and last block with 3DES
    """

    last_block = hex_to_byte(iv)
    cryptogram = []
    for i, block in enumerate(blocks):
        xor = do_xor(block, last_block)
        if dbg:
            print("Current block: {} Last Block: {}"
                  .format(block, byte_to_hex(last_block)))
            print("XOR: {}"
                  .format(byte_to_hex(xor)))

        last_block = encrypt_3des(sk, xor)
        if dbg:
            print("CB{}: {}"
                  .format(i, byte_to_hex(last_block)))
        cryptogram.append(byte_to_hex(last_block))
    if dbg:
        print("Cryptogram: {}"
              .format("".join(cryptogram)))

    return "".join(cryptogram)


def check_padding(data):
    """Adds padding to data if necessary

    Args:
        data: data to be analyzed, in hex string format

    Returns:
        Correctly padded data if necessary
    """

    tam = len(hex_to_byte(data))
    if tam != byte_block_size:
        padding = (byte_block_size - tam) * "00"
        data = data + padding
    return data


def split_hex(data, size):
    """Split a hex string by every size elements

    Args:
        data: data to be analyzed, in hex string format
        size: number of elements of each split, integer

    Returns:
        A string splitted by every size elements
    """

    return [data[i:i+size] for i in range(0, len(data), size)]


def calculate_session_key(admkey, getrsp):
    """Calculates the session key given the administrative key and the data
       from the getResponse

    Args:
        admkey: administrative key of 16B, in hex string format
        getrsp: getResponse answer (xxNTyyyyyyyyyyyyyCRN), in hex string format

    Returns:
        The session key
    """

    global sk
    admkey2admkey1 = admkey[16:]+admkey[:16]
    nt = getrsp[:4]
    nt_data = "000000" + nt + "000000"
    if dbg:
        print("DATA(NT): {}"
              .format(nt_data))
    sk1 = encrypt_3des(admkey, hex_to_byte(nt_data))
    if dbg:
        print("SK1: {}"
              .format(byte_to_hex(sk1)))

    sk2 = encrypt_3des(admkey2admkey1, hex_to_byte(nt_data))
    if dbg:
        print("SK2: {}"
              .format(byte_to_hex(sk2)))

    sk = byte_to_hex(sk1 + sk2)

    return sk


def read_input_action_1():
    """Reads data from stdin in order to calculate session key

    Returns:
        admkey: administrative key of 16B, in hex string format
        getrsp: getResponse answer (xxNTyyyyyyyyyyyyyCRN), in hex string format
    """

    global admkey
    if admkey is None:
        admkey = raw_input("Enter ADMKEY: ")
        assert len(hex_to_byte(admkey)) == 16, "ADMKEY has no 16B size"
        print("ADMKEY = " + " ".join(split_hex(admkey, 2)))
    else:
        yes = raw_input("ADMKEY in memory: {}\nUse this ADMKEY? [Y\\n]: "
                        .format(" ".join(split_hex(admkey, 2))))
        if yes == 'n':
            admkey = raw_input("Enter ADMKEY: ")
            assert len(hex_to_byte(admkey)) == 16, "ADMKEY has no 16B size"
            print("ADMKEY = {}"
                  .format(" ".join(split_hex(admkey, 2))))
        else:
            print("Using ADMKEY from memory")

    getrsp = raw_input("Enter getResponse answer after internal authenticate: ")
    assert len(hex_to_byte(getrsp)) == 10, "GetResponse has no 10B size"
    print("GetResponse = {}".format(" ".join(split_hex(getrsp, 2))))

    return admkey, getrsp


def read_input_action_2():
    """Reads data from stdin in order to check if data is correctly encrypted

    Returns:
        sk: session key of 16B, requested if not currently in memory,
            in hex string format
        ins: instructions of the command to be sent to the card of 5B,
             with L = L + 3
        data: data to be sent to the card, in hex string format
    """

    global sk
    if sk is None:
        sk = raw_input("Enter SK: ")
        assert len(hex_to_byte(sk)) == 16, "SK has no 16B size"
        print("SK = " + " ".join(split_hex(sk, 2)))
    else:
        yes = raw_input("SK in memory: {}\nUse this SK? [Y\\n]: "
                        .format(" ".join(split_hex(sk, 2))))
        if yes.lower() == 'n':
            sk = raw_input("Enter SK: ")
            assert len(hex_to_byte(sk)) == 16, "SK has no 16B size"
            print("SK = {}"
                  .format(" ".join(split_hex(sk, 2))))
        else:
            print("Using SK from memory")

    ins = raw_input("Enter instructions of the command to be sent to the card (with size + 3): ")
    assert len(hex_to_byte(ins)) == 5, "Instructions has no 5B size"
    print("INS = {}"
          .format(" ".join(split_hex(ins, 2))))

    data = raw_input("Enter data: ")
    print("DATA = {}"
          .format(" ".join(split_hex(data, 2))))

    return sk, ins, data


def read_input_action_3():
    """Reads data from stdin in order to calculate the cryptogram of data

    Returns:
        sk: session key of 16B, requested if not currently in memory,
            in hex string format
        data: data to be encrypted, in hex string format
    """

    global sk
    if sk is None:
        sk = raw_input("Enter SK: ")
        assert len(hex_to_byte(sk)) == 16, "SK has no 16B size"
        print("SK = {}"
              .format(" ".join(split_hex(sk, 2))))
    else:
        yes = raw_input("SK in memory: {}\nUse this SK? [Y\\n]: "
                        .format(" ".join(split_hex(sk, 2))))
        if yes.lower() == 'n':
            sk = raw_input("Enter SK: ")
            assert len(hex_to_byte(sk)) == 16, "SK has no 16B size"
            print("SK = {}"
                  .format(" ".join(split_hex(sk, 2))))
        else:
            print("Using SK from memory")

    data = raw_input("Enter data to be encrypted: ")
    assert len(hex_to_byte(data)) % 2 == 0, "Bad hexadecimal string"
    print("DATA = {}"
          .format(" ".join(split_hex(data, 2))))

    return sk, data


def main():
    print(""""Choose between the following actions:

    *1: Calculate session key, ask for administrative key and getResponse data.
    *2: Calculate last block in secure messaging, ask for session key
        if not already in memory, instructions to be sent to the card
        (with size + 3) and data to be sent.
    *3: Encrypt data, ask for session key if not already in memory
        and data to be encrypted.
    *4: Finish program.""")

    global sk

    while True:
        inp = raw_input("\nChoice: ")
        inp = int(inp)

        if inp == 1:
            if sk is not None:
                yes = raw_input("SK in memory: {}\nUse this SK? [Y\\n]: "
                                .format(" ".join(split_hex(sk, 2))))
                if yes.lower() == 'n':
                    admkey, getrsp = read_input_action_1()
                    sk = calculate_session_key(admkey, getrsp)

                print("SK: {}"
                      .format(sk))
            else:
                admkey, getrsp = read_input_action_1()
                sk = calculate_session_key(admkey, getrsp)
                print("SK: {}"
                      .format(sk))

        elif inp == 2:
            sk, ins, data = read_input_action_2()
            n_blocks = ceil((len(ins)/2.0 + len(data)/2.0)/8.0)
            assert n_blocks > 0, "At least one block must exists"
            blocks = []
            if n_blocks == 1:
                data = check_padding(data)
                blocks.append(data)
                blocks.append(8 * "00")
            else:
                to_split = ins + data
                blocks = split_hex(to_split, hex_block_size)
                blocks = [check_padding(block) for block in blocks]

            print("Last block: {}"
                  .format(byte_to_hex(calculate_last_block(blocks, sk))))

        elif inp == 3:
            sk, data = read_input_action_3()
            blocks = split_hex(data, hex_block_size)
            blocks = [check_padding(block) for block in blocks]
            print("CDATA: {}"
                  .format(calculate_cryptogram(blocks, sk)))

        elif inp == 4:
            print("Exiting")
            break
        else:
            print("Error, choose one activity between 1 and 4")


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "-d":
        global dbg
        dbg = True
    main()
