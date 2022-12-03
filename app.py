import os
import json

import flask
from flask import Flask, redirect, url_for, request, jsonify
from flask_login import (LoginManager, current_user, login_required, login_user, logout_user, UserMixin)
import requests
from oauthlib.oauth2 import WebApplicationClient
import time
from datetime import date, datetime
import pymongo
from pymongo import MongoClient
import numpy
from flask_cors import CORS
from bson.objectid import ObjectId

import db
from user import User

app = Flask(__name__)
app.secret_key =  os.urandom(24) # or os.environ.get("SECRET_KEY")
CORS(app)


#Google auth config
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", None)
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", None)
GOOGLE_DISCOVERY_URL = ("https://accounts.google.com/.well-known/openid-configuration")


# fix CORS issues?
app.config["Access-Control-Allow-Origin"] = "*"


# setup login manager
login_manager = LoginManager()
login_manager.init_app(app)


# oauth2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()
    # add error checking?


################################
# Database Interactions
################################

def dbi_shutdown():
    db.shutdown_db_client()


def dbi_create_poll(dat):
    return db.create_poll(dat)

def dbi_get_poll(pid):
    return db.get_poll(pid)


def dbi_update_poll(dat):
    return db.update_poll(dat)


def dbi_delete_older_than(tar_date):
    db.delete_older_than(tar_date)

"""
def dbi_nuke():
    db.nuke_it_from_orbit()
"""

def dbi_create_user(dat):
    return db.create_user(dat)


def dbi_get_user(uid):
    return db.get_user(uid)


def dbi_update_user(dat):
    return db.update_user(dat)


################################
# Login APIs
################################

@app.route("/checklogin")
def index():
    print("Hit on homepage")
    if current_user.is_authenticated:
        print("Current user id: " + current_user.id + " user name: " + current_user.name)
        return (
            "<p>Hello, {}! You're logged in! Email: {}</p>"
            "<div><p>Google Profile Picture:</p>"
            '<img src="{}" alt="Google profile pic"></img></div>'
            '<a class="button" href="/logout">Logout</a>'.format(current_user.name, current_user.email, current_user.profile_pic)
        )
    else:
        return '<a class="button" href="/login">Google Login</a>'


@app.route("/login")
def login():
    print("Start login attempt")
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)


@app.route("/login/callback")
def callback():
    print("Login callback")
    code = request.args.get("code")
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]
    token_url, headers, body = client.prepare_token_request(
        token_endpoint, authorization_response=request.url, redirect_url=request.base_url, code=code)
    token_response = requests.post(token_url, headers=headers, data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET))
    client.parse_request_body_response(json.dumps(token_response.json()))
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)
    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["given_name"]
    else:
        return "User email not available or not verified by Google.", 400
    # Create a user in your db with the information provided
    # by Google
    user = User(
        id_=unique_id, name=users_name, email=users_email, profile_pic=picture
    )
    # Doesn't exist? Add it to the database.
    if not User.get(unique_id):
        User.create(unique_id, users_name, users_email, picture)
    
    print ("got user id: " + user.id + " - user name: " + user.name)
    # Begin user session by logging the user in
    login_user(user)
    # login_user(user, remember=True)

    # Send user back to homepage
    return redirect(url_for("index"))


@app.route("/logout")
#@login_required
def logout():
    print("Logout")
    logout_user()
    return redirect(url_for("index"))


################################
# General APIs
################################


# Create poll
@app.route("/createpoll", methods=["POST"])
def createpoll():
    j = request.values.get("json_data")
    data = json.loads(j)
    today = date.today()
    data["create_date"] =  today.strftime("%y/%m/%d")
    data["members"] = []
    if current_user.is_authenticated:
        uid = current_user.id
        data["members"].append( {"name":current_user.name, "id":uid} )
    else:
        if data["allow_guest"] == False:
            return {"Message":"Guest polls must allow guest users"}, 400
    for q in data["questions"]:
        a_list = []
        for a in q["answers"]:
            a_text = a
            a_temp = {"a_text":a_text, "people":[] }
            a_list.append(a_temp)
        q["answers"] = a_list
    x = dbi_create_poll(data)
    pid = x.inserted_id
    if current_user.is_authenticated:
        # add pid to user's list of polls
        add_poll_to_user(current_user.id, pid, True)
    retval = { 'pid': x.inserted_id }
    return retval, 201


# Get poll data
@app.route("/poll/<poll_id>")
def getpoll(poll_id):
    id = ObjectId(poll_id)
    p_data = dbi_get_poll(id)
    
    if p_data is None:
        # return {"Message":"Could not find poll"}, 404
        print("Could not find poll")
    elif ((not current_user.is_authenticated) and (not p_data["allow_guest"])):
        # return {"Message":"This poll does not allow guest access"}, 401
        print("This poll does not allow guest access")
    else:
        return p_data, 200


# Update poll
@app.route("/update", methods=["POST"])
def update(id):
    j = request.values.get("json_data")
    data = json.loads(j)
    
    p = dbi_get_poll(data["poll_id"])
    # check if access is allowed
    if ((not current_user.is_authenticated) and (not p["allow_guest"])):
        return {"Message":"Guests can not modify this poll"}, 401
    if ((p["p_pw"] != "") and (p["p_pw"] != data["p_pw"])):
        return {"Message":"Password does not match"}, 401
    # build entry
    entry = {"p_name": p["p_name"], "p_pw":p["p_pw"], "allow_guest": p["allow_guest"],
            "date_start": p["date_start"], "date_end": p["date_end"], "index_start": p["index_start"],
            "index_end": p["index_end"], "containers": p["containers"], "questions": p["questions"],
            "members": p["members"], "times":p["times"], "_id":p["_id"]}
    # get uid and/or name if valid
    # add to poll["members"] if not present
    u = { "name": "", "id": "" }
    if current_user.is_authenticated:
        u["id"] = current_user.id
        u["name"] = current_user.name
    elif (data["u_name"] != ""):
        u["name"] = data["u_name"]
    else:
        return {"Message":"Must specify a user name"}, 400
    if u not in p["members"]:
        data["members"].append(u)
    # get member index of the updating user
    u_index = find_member_index(u["name"], p["members"])
    
    # process times
    d_len = p["index_start"] - p["index_end"] + 1
    d1 = datetime.strptime(p["date_start"], "%Y/%m/%d")
    d2 = datetime.strptime(p["date_end"], "%Y/%m/%d")
    d_delta = d2 - d1
    days = d_delta.days + 1
    for t_index, t_entry in enumerate(entry["times"]):
        # iterate through entry["times"]
        # match to appropriate day and time in data["times"]
        # if value in data is True, add user to that entry if not present
        # if False, remove from that entry if present
        di = t_index / d_len
        ti = t_index % d_len
        if data["times"][di][ti]:
            if u_index not in t_entry:
                t_entry.append(u_index)
        else:
            if u_index in t_entry:
                t_entry.remove(u_index)
    
    # process containers
    # go through data containers, compare to entry containers
    # if item not present in entry, add it (with user)
    for dcont in data["items"]:
        c_name = dcont["name"]
        # find equivalent entry container
        e_cont = None
        for ec in entry["containers"]:
            if (ec["name"] == c_name):
                e_cont = ec
                break
        if e_cont:
            # equiv container found, proceed
            # should always be true since we don't delete containers
            for d_item in dcont["items"]:
                # find equiv entry item
                e_item = None
                for ei in e_cont["items"]:
                    if (ei["name"] in d_item):
                        e_item = ei
                        break
                if (e_item == None):
                    # item not in entry, add it
                    newitem = {"name":d_item, "people": [u_index] }
                    e_cont["items"].append(newitem) 
    # then, go through containers in entry, compare to equiv in submitted data
    # if item exists, ensure it has user in entry people list
    # if it doesn't exist, remove user from entry item
    for cont in entry["containers"]:
        c_name = cont["name"]
        # find equivalent container in submitted data
        d_cont = None
        for dc in data["items"]:
            if (dc["name"] == c_name):
                d_cont = dc
                break
        if d_cont:
            # equivalent container found, proceed
            for e_item in cont["items"]:
                if e_item["name"] in d_cont["items"]:
                    # item exists in submitted data, ensure user is present in entry
                    if u_index not in e_item["people"]:
                        e_item["people"].append(u_index)
                else:
                    # item doesn't exist, remove user from entry if present
                    if u_index in e_item["people"]:
                        e_item["people"].remove(u_index)
    # current implementation keeps empty items so they don't disappear if nobody selects them
    
    # process questions
    # go through all answers in entry.
    # if present in submitted data, add user (if not present)
    # if not present in submitted data, remove user (if present)
    for eq in entry["questions"]:
        q_name = eq["question"]
        # find equivalent question in submitted data
        d_quest = None
        for dq in data["questions"]:
            if (dq["question"] == q_name):
                d_quest = dq
                break
        if d_quest:
            # question found, proceed
            for e_ans in eq["answers"]:
                # find equivalent answer in submitted data
                if (e_ans["a_text"] in d_quest["answers"]):
                    # answer found, add user if absent
                    if u_index not in e_ans["people"]:
                        e_ans["people"].append(u_index)
                else:
                    # answer not found, remove user if present
                    if u_index in e_ans["people"]:
                        e_ans["people"].remove(u_index)
        else:
            # question not found, remove user from answers!
            for ea in eq["answers"]:
                if u_index in ea["people"]:
                    ea["people"].remove(u_index)
    
    # all fields filled, write update:
    x = dbi_update_poll(entry)
    if (x.matched_count == 0):
        return {"Message":"Poll does not exist to modify"}, 404
    else:
        # poll updated, send success, add to user's "members" list
        if current_user.is_authenticated:
            add_poll_to_user(current_user.id, p["_id"], False)
        return {"Message":"Update success"}, 200


@app.route("/profile")
def profile():
    if current_user.is_authenticated:
        uid = current_user.id
        u = dbi_get_user(uid)
        u_data = {}
        u_data["polls_owned"] = u["polls_own"]
        u_data["polls_member"] = u["polls_member"]
        u_tata["save_schedules"] = u["schedules"]
        return u_data, 200
    else:
        return {"Message":"User is not logged in"}, 400


@app.route("/saveschedule", methods=["POST"])
def saveschedule():
    if current_user.is_authenticated:
        j = request.values.get("json_data")
        data = json.loads(j)
        # validate data
        if (data["s_name"] == ""):
            return {"Message":"Schedule must have a name"}, 400
        if (len(data["s_data"]) != 672):
            return {"Message":"Schedule data is of wrong length"}, 400
        for x in data["s_data"]:
            if ((x is not True ) or (x is not False)):
                return {"Message":"Schedule data malformed; only True or False allowed"}, 400
        # looks good, save it
        uid = current_user.id
        u = dbi_get_user(uid)
        write = False
        for x in u["schedules"]:
            if (x["name"] == data["s_name"]):
                x["schedule"] = data["s_data"]
                write = True
                break
        if not write:
            u["schedules"].append( {"name": data["s_name"], "schedule": data["s_data"]} )
        y = dbi_update_user(u)
        if (y.matchedCount == 0):
            return {"Message":"Could not find user to modify"}, 404
        else:
            return {"Message":"Update success"}, 200
    else:
        return {"Message":"User is not logged in"}, 400


@app.route("/getschedulestring", methods=["POST"])
def getschedulestring():
    j = request.values.get("json_data")
    data = json.loads(j)
    # first, look for saved schedules:
    if (current_user.is_authenticated and (s_name != "")):
        uid = current_user.id
        u = dbi_get_user(uid)
        for x in u["schedules"]:
            if (x["name"] == data["s_name"]):
                packed = sched_to_string(x["schedule"])
                return packed, 200
        return {"Message":"Could not find specified schedule"}, 400
    # otherwise check supplied s_data
    else:
        if (len(data["s_data"]) != 672):
            return {"Message":"Schedule data is of wrong length"}, 400
        for x in data["s_data"]:
            if ((x is not True ) or (x is not False)):
                return {"Message":"Schedule data malformed; only True or False allowed"}, 400
        # looks good, convert it
        packed = sched_to_string(data["s_data"])
        return packed, 200


@app.route("/uploadschedulestring", methods=["POST"])
def uploadschedulestring():
    j = request.values.get("json_data")
    data = json.loads(j)
    sched = string_to_sched(data["s_string"])
    # validate data
    if (len(data["s_data"]) != 672):
        return {"Message":"Schedule data is of wrong length"}, 400
    for x in data["s_data"]:
        if ((x is not True ) or (x is not False)):
            return {"Message":"Schedule data malformed; only True or False allowed"}, 400
    # okay, continue
    pid = data["poll_id"]
    p = dbi_get_poll(pid)
    days = [ [], [], [], [], [], [], [] ]
    start = p["index_start"]
    end = p["index_end"]
    # notice: frontend treats day 0 as Sunday
    # saved schedules will also have this behavior
    for i, info in enumerate(sched):
        if ( ((i % 96) < start) or ((i % 96) > end)):
            continue
        times[(i / 96) % 7][i % 96]
    # days constructed, update poll times
    # build entry
    entry = {"p_name": p["p_name"], "p_pq":p["p_pw"], "allow_guests": p["allow_guests"],
            "date_start": p["date_start"], "date_end": p["date_end"], "index_start": p["index_start"],
            "index_end": p["index_end"], "containers": p["containers"], "questions": p["questions"],
            "members": p["members"], "times":p["times"]}
    # get uid and/or name if valid
    # add to poll["members"] if not present
    u = { "name": "", "id": "" }
    if current_user.is_authenticated:
        u["id"] = current_user.id
        u["name"] = current_user.name
    elif (data["u_name"] != ""):
        u["name"] = data["u_name"]
    else:
        return {"Message":"Must specify a user name"}, 400
    if u not in p["members"]:
        data["members"].append(u)
    # get member index of the updating user
    u_index = find_member_index(u["name"], p["members"])
    # process times
    d_len = p["index_start"] - p["index_end"] + 1 # time periods per day
    d1 = datetime.strptime(p["date_start"], "%Y/%m/%d")
    d2 = datetime.strptime(p["date_end"], "%Y/%m/%d")
    d_delta = d2 - d1
    days = d_delta.days + 1 # number of days
    max = days * d_len # total number of time periods in poll
    dow_start = d1.weekday() # day of week of first day (where Monday == 0)
    # iterate through all times in entry
    # for each time slot, check boolean in equivalent entry in days list
    # if true, add u_index if absent
    # if false, remove u_index if present
    for counter, t_entry in enumerate(entry["times"]):
        # schedule treats 0 as Sunday
        # target_day must +1 to get right days index
        target_day = ((counter / d_len) + dow_start + 1) % 7
        target_time = counter % d_len
        if days[target_day][target_time]:
            # true, add u_index if absent
            if u_index not in t_entry:
                t_entry.append(u_index)
        else:
            # false, remove u_index if present
            if u_index in t_entry:
                t_entry.remove(u_index)
    return {"Message":"Update success"}, 200


# Delete all database entries. Don't use unless you mean it!
# Do not include this in release! For testing only!
"""
@app.route("/nukem")
def nukem():
    dbi_nuke()
"""

################################
# Helper Functions
################################

# if owned, check and add to polls_own
# owned == false, check if in polls_own, add to polls_member if not present
# owned == true, add it to the "polls_own" list if not present
def add_poll_to_user(uid, pid, owned):
    u = dbi_get_user(uid)
    if pid not in u["polls_own"]:
        if owned:
            u["polls_own"].append(pid)
            dbi_update_user(u)
        elif pid not in u["polls_member"]:
            u["polls_member"].append(pid)
            dbi_update_user(u)


def sched_to_string(sched):
    arr = numpy.array(sched, dtype=bool)
    packed = numpy.packbits(arr, axis=None)
    str = numpy.array2string(packed)
    return packed


def string_to_sched(str):
    packed = numpy.fromstring(str, dtype=uint8, sep=' ')
    arr = numpy.unpackbits(packed)
    arr_bool = arr.astype(bool)
    return arr_bool.tolist()


def find_member_index(n, arr):
    # print("Looking for: ", n)
    for i, user in enumerate(arr):
        # print("Looking at ", user["name"])
        if (n == user["name"]):
            return i
    return -1 # indicates error


"""
def add_user_to_poll(uid, pid):
    p = dbi_get_poll(pid)
    if find_user_in_poll(uid, p) is None:
        p["members"].append(


def find_user_in_poll(uid, poll)
    for m in poll["members"]:
        if (m["id"] == uid):
            return m
    return None
"""

################################
# Main
################################

def main():
    print("Starting app!")
    #app.run(debug=True, ssl_context='adhoc')
    app.run(ssl_context='adhoc')
    
    # Testing
    """
    # test poll db functions
    dbi_nuke()
    today = date.today()
    ds = today.strftime("%y/%m/%d")
    ptest = { "p_name": "Testpoll", "p_pw": "12345", "allow_guest": True,
            "date_start": "11/21/2022", "date_end": "11/22/2022", "index_start": 0,
            "index_end": 95, "containers": [], "questions": [],
            "create_date": ds }
    x = dbi_create_poll(ptest)
    pid = x.inserted_id
    print("Created poll with id: ", pid)
    utest = { "_id" : pid, "p_name": "Testpoll", "p_pw": "12345", "allow_guest": True,
            "date_start": "11/21/2022", "date_end": "11/22/2022", "index_start": 32,
            "index_end": 95, "containers": [], "questions": [] }
    x = dbi_update_poll(utest)
    print(x.modified_count, " documents modified")
    gtest = dbi_get_poll(pid)
    print("Got poll:")
    print(gtest)
    dbi_nuke()
    """
    
    """
    # test user db functions
    dbi_nuke()
    utest = {"id": 23, "u_name":"Terika", "email":"none", "profile_pic":"nono"}
    x = dbi_create_user(utest)
    uid = x.inserted_id
    print("Created user with id: ", uid)
    gutest = dbi_get_user(uid)
    print("Got user:")
    print(gutest)
    dbi_nuke()
    """
    
    """
    # test user db poll membership function
    dbi_nuke()
    utest = {"id": 23, "u_name":"Terika", "email":"none", "profile_pic":"nono"}
    u = dbi_create_user(utest)
    uid = u.inserted_id
    print("Created user with id: ", uid)
    gutest = dbi_get_user(uid)
    print("Got user:")
    print(gutest)
    today = date.today()
    ds = today.strftime("%y/%m/%d")
    ptest = { "p_name": "Testpoll", "p_pw": "12345", "allow_guest": True,
            "date_start": "11/21/2022", "date_end": "11/22/2022", "index_start": 0,
            "index_end": 95, "containers": [], "questions": [],
            "create_date": ds, "members": [{"name":"Terika", "id":23}] }
    x = dbi_create_poll(ptest)
    pid = x.inserted_id
    print("Adding poll ", pid, " to user ", uid)
    add_poll_to_user(uid, pid, True)
    gutest = dbi_get_user(uid)
    print("Got user:")
    print(gutest)
    dbi_nuke()
    """
    
    """
    # test poll creation and retrieval
    temp_id = createpoll()
    test_id = temp_id["pid"]
    print("Created poll with ID: ", test_id)
    dat = getpoll(test_id)
    print(dat)
    """
    
    """
    # test retreiving existing poll
    test_id = '63892d82a06be51d7a47eebe'
    dat = getpoll(test_id)
    print(dat)
    """
    
    """
    # test poll creation and retrieval
    temp_id = createpoll()
    test_id = temp_id["pid"]
    print("Created poll with ID: ", test_id)
    dat = getpoll(test_id)
    print(dat)
    update(test_id)
    dat = getpoll(test_id)
    print(dat)
    dbi_nuke()
    """

if __name__ == "__main__":
    main()