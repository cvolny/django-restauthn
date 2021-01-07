import base64
import cbor2
from pprint import pprint

from rest_framework.renderers import BaseRenderer, BrowsableAPIRenderer, JSONRenderer
from .parsers import *


def r_encode(x, enc=base64.b64encode):
    """
    Recursively encode values in x.
    """
    if isinstance(x, bytes):
        return enc(x)
    elif isinstance(x, dict):
        return {k: r_encode(v, enc) for k, v in x.items()}
    elif isinstance(x, (list, tuple)):
        return (r_encode(y, enc) for y in x)
    else:
        return x


class CborRenderer(BaseRenderer):
    media_type = "application/cbor"
    format = "cbor"
    charset = None
    render_style = "binary"

    def render(self, data, *args, **kwargs):
        return cbor2.dumps(data)

class Base64CborRenderer(BaseRenderer):
    media_type = "text/plain"
    format = "txt"
    charset = "utf-8"

    def render(self, data, *args, **kwargs):
        return base64.b64encode(cbor2.dumps(data))

class Base64JsonRenderer(JSONRenderer):
    def render(self, data, *args, **kwargs):
        return super().render(r_encode(data), *args, **kwargs)


class CborBrowsableAPIRenderer(BrowsableAPIRenderer):
    def get_default_renderer(self, view):
        return Base64JsonRenderer()
