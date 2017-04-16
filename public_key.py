import binascii

def binconvert(n):
    barray = []
    if n < 0:
        raise ValueError, "must be positive"
    if n == 0:
        return 0
    while n > 0:
        # barray = n%2 + barray[:]
        barray.append(n % 2)
        n = n >> 1
    barray.reverse()
    return barray

# y**x mod n
def modexp(y, x, n):
    # convert x to a binary list
    x = binconvert(x)

    s = [1]
    r = x[:]
    for k in range(0, len(x)):
        if x[k] == 1:
            r[k] = (s[k] * y) % n
        else:
            r[k] = s[k]
        s.append((r[k] ** 2) % n)
    # print s
    # print r
    return r[-1]


def bigint_to_bytes(x):
    hex_string = '%x' % x
    if len(hex_string) % 2 == 1:
        hex_string = '0' + hex_string
    return binascii.unhexlify(hex_string)