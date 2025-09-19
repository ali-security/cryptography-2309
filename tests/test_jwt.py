from cryptography.exceptions import InvalidSignature, InternalError
from jwt.algorithms import get_default_algorithms


def test_jwt():
    verifier = get_default_algorithms()["RS256"]
    pk = verifier.from_jwk({
        "kty": "RSA",
        "n": "tHbYl75dwWTcdrRBODUipsQ7qFfF7uGHGnP0eYI33dk0OW3lG_qh09dyPHQUeEXlcHBoWf-K08ofpl0jhequ5vvvN92PU-wL0qYNMXk2FCtLneUM8FzDEyLoKG_mMsrU-qnwvlw83vqdp9FPa8Ja2ImPooma_amsr3oW7vYhFYhr4R7F5Ph9CgIO4Lu8zkl1ZzqRdlIRkpjW-IDVKZlPZ2alNJlTUiqeS3rOdNn8y5ez9EUOreUhfsS8m39FbrJvNQEsA0DHeuVnIG_eDmKZ928HCcJh2CNOL4gY2cD9qoWOYx4e3RHUaXQn_p6MEmjxql4vL6-K99oOQYDN6ZdDr7gjHiSen7D5PZQtzJohIZBEqTEU2yLh8U8vQPqP5OqCx87hwwEqoHc80SLY4qSQhJOf1CayuuZQsBie3Sp21SsGXLLr9jCNPogKGbmOmpWaspXRdpFr6ep_DUpi3-qFO4_xBUkKj_08GsBW9sDj8btyhI2Wygc7n8D_PyQy8cWOc4we8E2xQ8mJwIevVE0--HoIy-M8QxdBly5igZalbOUx-qoPMOOdi07JA5o13HbTjdJA68XCBB3mWsqaiufGbjLlHaZ-tRnL1VNWopDHwLkIQmIFkGtpkt9aivMiRsnNK3pzg420rfOqbeCeWEl3mXYM_9v0BezbQg2OKlbn9Xc",
        "e": "AQAB"
    })
    try:
        verifier.verify(b"some message", pk, b"invalid signature")
    except InvalidSignature:
        pass  # We don't have a valid signature, so expect this to fail.

