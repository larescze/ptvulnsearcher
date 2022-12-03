import json
from os import abort
from flask import Flask, jsonify
from flask_restful import Api, Resource, fields, marshal_with
from sqlalchemy import  ForeignKey



#DB connection
app = Flask(__name__)


@app.route("/root/<string:first>/<string:last>")
@app.route("/root/<string:first>")
def get(first = None, last=None):
    if (first and last) != None:
        return f"{first} {last}"
    elif(first != None):
        return f"{first}"
    elif(last != None):
        return f"{last}"
    else:
        return "Err"
    


app.run(debug=True)