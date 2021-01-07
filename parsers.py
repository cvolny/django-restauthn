import base64
import cbor2
import io
import json

from rest_framework.parsers import BaseParser
from .renderers import *


class CborParser(BaseParser):
    media_type = "application/cbor"
    renderer_class = CborRenderer

    def parse(self, stream, *args, **kwargs):
        return cbor2.load(stream)

class Base64CborParser(BaseParser):
    media_type = "text/plain"
    renderer_class = Base64CborRenderer

    def parse(self, stream, *args, **kwargs):
        data = base64.b64decode(stream.read())
        return cbor2.loads(data)
