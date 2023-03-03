__author__ = "Tejaskumar Kasundra(tejaskumar.kasundra@gmail.com)"

from . import app
from . import views


if __name__ == "__main__":
    app.run(host='127.0.0.1', port=3000, debug=True)
