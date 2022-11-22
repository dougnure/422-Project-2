import os
import json

import flask
from flask import Flask, redirect, url_for, request, jsonify
from flask_login import (LoginManager, current_user, login_required, login_user, logout_user, UserMixin)
import requests
from oauthlib.oauth2 import WebApplicationClient
from datetime import date
import pymongo
from pymongo import MongoClient

#import db
#from user import User

app = Flask(__name__)
# app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)


################################
# Database Module
################################


#def init_connection():
m_client = pymongo.MongoClient("mongodb+srv://schedule_master:mRwU0GM02nMk6nVV@cluster0.xlxwx34.mongodb.net/?retryWrites=true&w=majority")
db = m_client.polltogether
c_poll = db["polls"]
c_user = db["users"]

def shutdown_db_client():
    m_client.close

def create_poll(dat):
    print("Create poll called")
    entry = { "p_name": dat["p_name"], "p_pw": dat["p_pw"], "allow_guest": dat["allow_guest"],
            "date_start": dat["date_start"], "date_end": dat["date_end"], "index_start": dat["index_start"],
            "index_end": dat["index_end"], "containers": dat["containers"], "questions": dat["questions"],
            "create_date": dat["create_date"] }
    print("poll data loaded to entry. Entry:")
    print(entry)
    return c_poll.insert_one(entry)

def get_poll(pid):
    return c_poll.find_one( {"_id": pid},{"_id":1, "create_date":0} )

def update_poll(dat):
    entry = { "p_name": dat["p_name"], "p_pw": dat["p_pw"], "allow_guest": dat["allow_guest"],
            "date_start": dat["date_start"], "date_end": dat["date_end"], "index_start": dat["index_start"],
            "index_end": dat["index_end"], "containers": dat["containers"], "questions": dat["questions"] }
    pid = dat["_id"]
    return c_poll.update_one( {"_id": pid}, {"$set": entry} )
    # <return>.matchedCount == number of documents found
    # <return>.modifiedCount == number of documents modified

def delete_older_than(tar_date):
    pass

def nuke_it_from_orbit():
    # only uncomment and use if you really mean it
    x = c_poll.delete_many({})
    print(x.deleted_count, " polls deleted")
    x = c_user.delete_many({})
    print(x.deleted_count, " users deleted")
    return


################################
# APIs
################################
# Currently only implementing guest actions!


# Create poll
@app.route("/createpoll")
def createpoll():
    j = request.values.get("json_data")
    data = json.loads(j)
    data["current_date"] = date.today()
    #x = db.create_poll(data)
    x = create_poll(data)
    pid = x.inserted_id
    retval['pid':x.inserted_id]
    return retval, 201


# Get poll data
@app.route("/poll/<poll_id>")
def getpoll(poll_id):
    #p_data = db.get_poll(poll_id)
    p_data = get_poll(poll_id)
    if p_data is None:
        return {"Message":"Could not find poll"}, 404
    else:
        return p_data, 200


# Update poll
@app.route("/update")
def update():
    j = request.values.get("json_data")
    data = json.loads(j)
    #x = db.update_poll(data)
    x = update_poll(data)
    if (x.matchedCount == 0) or (x.modifiedCount == 0):
        return {"Message":"Poll does not exist to modify"}, 404
    else:
        return {"Message":"Update success"}, 200


# Delete all database entries. Don't use unless you mean it!
# Do not include this in release! For testing only!
@app.route("/nukem")
def nukem():
    nuke_it_from_orbit()


def main():
    print("Starting app!")
    #db.init_connection()
    
    # Testing
    """
    nukem()
    today = date.today()
    ds = today.strftime("%y/%m/%d")
    ptest = { "p_name": "Testpoll", "p_pw": "12345", "allow_guest": True,
            "date_start": "11/21/2022", "date_end": "11/22/2022", "index_start": 0,
            "index_end": 95, "containers": [], "questions": [],
            "create_date": ds }
    x = create_poll(ptest)
    pid = x.inserted_id
    print("Created poll with id: ", pid)
    utest = { "_id" : pid, "p_name": "Testpoll", "p_pw": "12345", "allow_guest": True,
            "date_start": "11/21/2022", "date_end": "11/22/2022", "index_start": 32,
            "index_end": 95, "containers": [], "questions": [] }
    x = update_poll(utest)
    print(x.modified_count, " documents modified")
    gtest = get_poll(pid)
    print("Got poll:")
    print(gtest)
    
    nukem()
    """
    
    # App
    app.run(debug=True, ssl_context='adhoc')


if __name__ == "__main__":
    main()