from flask import Flask
from flask_sqlalchemy import SQLAlchemy


#DB connection
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///postgres:postgres@localhost/postgres"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

database = SQLAlchemy(app)


#Creating model

class cveTable(database.Model):
    id = database.Column(database.Integer(),primary_key=True)
    cve_id = database.Column(database.String(17), nullable = False)
    cwe_id = database.Column(database.String(15), nullable = True)
    cvss_vector = database.Column(database.String(40), nullable = True)
    cvss_score = database.Column(database.Float, nullable = True)
    description = database.Column(database.Text, nullable = True)


class vendorTable(database.Model):
    product_id = database.Column(database.Integer(),primary_key=True)
    cve_id = database.Column(database.String(17), nullable = False)
    vendor = database.Column(database.Text, nullable = True)
    product_type = database.Column(database.String(11), nullable = True)
    product_name = database.Column(database.Text, nullable = True)
    version = database.Column(database.String(8), nullable = True)
    





@app.route("/")
def hello():
    return "Hello"


app.run()