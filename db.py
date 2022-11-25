import pymongo
from pymongo import MongoClient


m_client = pymongo.MongoClient("mongodb+srv://schedule_master:mRwU0GM02nMk6nVV@cluster0.xlxwx34.mongodb.net/?retryWrites=true&w=majority")
db = m_client.polltogether
c_poll = db["polls"]
c_user = db["users"]


################################
# General DB functions
################################

def shutdown_db_client():
    m_client.close


def nuke_it_from_orbit():
    # only uncomment and use if you really mean it
    x = c_poll.delete_many({})
    print(x.deleted_count, " polls deleted")
    x = c_user.delete_many({})
    print(x.deleted_count, " users deleted")
    return


################################
# Poll DB functions
################################

# calling API loads creating user into "members", if valid!
def create_poll(dat):
    print("Create poll called")
    entry = { "p_name": dat["p_name"], "p_pw": dat["p_pw"], "allow_guest": dat["allow_guest"],
            "date_start": dat["date_start"], "date_end": dat["date_end"], "index_start": dat["index_start"],
            "index_end": dat["index_end"], "containers": dat["containers"], "questions": dat["questions"],
            "create_date": dat["create_date"], "members": dat["members"] }
    print("poll data loaded to entry. Entry:")
    print(entry)
    return c_poll.insert_one(entry)


def get_poll(pid):
    return c_poll.find_one( {"_id": pid},{"_id":1, "create_date":0} )


def update_poll(dat):
    entry = { "p_name": dat["p_name"], "p_pw": dat["p_pw"], "allow_guest": dat["allow_guest"],
            "date_start": dat["date_start"], "date_end": dat["date_end"], "index_start": dat["index_start"],
            "index_end": dat["index_end"], "containers": dat["containers"], "questions": dat["questions"],
            "members": dat["members"]}
    pid = dat["_id"]
    return c_poll.update_one( {"_id": pid}, {"$set": entry} )
    # <return>.matchedCount == number of documents found
    # <return>.modifiedCount == number of documents modified


def delete_older_than(tar_date):
    pass


def delete_poll(pid):
    pass


################################
# User DB functions
################################

# create user from dat (id, name, email, profile_pic)
def create_user(dat):
    entry = {"_id": dat["id"], "u_name": dat["u_name"], "email": dat["email"], "profile_pic": dat["profile_pic"],
            "polls_own": [], "polls_member": [], "schedules": [] }
    print("user data loaded to entry. Entry:")
    print(entry)
    return c_user.insert_one(entry)

# get user data and return it
def get_user(uid):
    return c_user.find_one( {"_id": uid} )


def update_user(dat):
    entry = {"_id": dat["id"], "u_name": dat["u_name"], "email": dat["email"], "profile_pic": dat["profile_pic"],
            "polls_own": dat["polls_own"], "polls_member": dat["polls_member"], "schedules": dat["schedules"] }
    pid = dat["_id"]
    return c_user.update_one( {"_id": uid}, {"$set": entry})