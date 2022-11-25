from flask_login import UserMixin

#from db import get_user, create_user
import db

################################
# Database Interactions
################################

def dbi_create_user(dat):
    return db.create_user(dat)

def dbi_get_user(uid):
    return db.get_user(uid)


################################
# User Class
################################

class User(UserMixin):
    def __init__(self, id_, name, email, profile_pic, polls_own, polls_member, schedules):
        self.id = id_
        self.name = name
        self.email = email
        self.profile_pic = profile_pic
        self.polls = polls
        self.schedules = schedules

# needs db.get_user()
    @staticmethod
    def get(user_id):
        print("Called get user")
        user = dbi_get_user(user_id)
        if not user:
            return None
        ruser = User(id_=user["_id"], name=user["u_name"], email=user["email"], profile_pic=user["profile_pic"],
                    polls_own = [], polls_member = [], schedules = [])
        return ruser

#needs db.create_user
    @staticmethod
    def create(id_, name, email, profile_pic):
        print("Called create user")
        # {"_id": dat["id"], "u_name": dat["u_name"], "email": dat["email"], "profile_pic": dat["profile_pic"] }
        dat = { "id":id_, "u_name":name, "email":email, "profile_pic":profile_pic,
                "polls_own": [], "polls_member": [], "schedules": [] }
        dbi_create_user(dat)