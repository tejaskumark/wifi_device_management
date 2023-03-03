__author__ = "Tejaskumar Kasundra(tejaskumar.kasundra@gmail.com)"

from flask import Flask  # import main Flask class and request object
from pathlib import Path

app = Flask(__name__)  # create the Flask app

app.config['DEBUG'] = True  # some Flask specific configs
