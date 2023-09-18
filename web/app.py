from flask import Flask, jsonify, request
from flask_restful import Api, Resource
import os
import bcrypt

from pymongo import MongoClient

app=Flask(__name__)
api = Api(app)

client=MongoClient("mongodb://db:27017")
db=client.MessageDatabase
users=db["Users"]

class Register(Resource):
    def post(self):
        postedData=request.get_json()

        #RETRIEVE USER NAME AND PASSWORD
        username=postedData["username"]
        password=postedData["password"]

        #store username and password
        hashed_pw=bcrypt.hashpw(password.encode('utf8'),bcrypt.gensalt())
        #storing password using hashing
        users.insert_one({
            "Username":username,
            "Password": hashed_pw,
            "Message": "",
            "Tokens":6
        }) 

        retJson={
            "status":200,
            "msg":"You have successfully signed up for the API"
        }   

        return jsonify(retJson)

def verifyPw(username,password):
    hashed_pw=users.find({
        "Username":username
    })[0]["Password"]

    if bcrypt.hashpw(password.encode('utf8'),hashed_pw)==hashed_pw:
        return True
    else:
        return False    

def countTokens(username):
    tokens=users.find({
        "Username":username
    })[0]["Tokens"]

    return tokens

class Store(Resource):
    def post(self):
        #Step 1:Get the posted data
        postedData=request.get_json()
        #Step 2 : Readthe data
        username=postedData["username"]
        password=postedData["password"]
        message=postedData["message"]
        #Step 3: Verify the username and password match
        correct_pw=verifyPw(username, password)
        
        if not correct_pw:
            retJson={
                "status":302,
                "msg":"incorrect password"
            }
            return jsonify(retJson)
        #Step 4: Verify that the user has enough tokens
        num_tokens=countTokens(username)
        if num_tokens<=0:
            retJson={
                "status":301,
                "msg":"User is out of Tokens"
            }
        #Step5: Store the message, take one token away, return 200

        users.update_one({
            "Username":username
        },
        {
        "$set":{
            "Message":message,
            "Tokens":num_tokens-1
        }    
        })

        retJson={
            "status":200,
            "msg": "Message saved Successfully"
        }
        return jsonify(retJson)

class Get(Resource):
    def post(self):
        postedData=request.get_json()
        username=postedData["username"]
        password=postedData["password"]

        correct_pw=verifyPw(username,password)
        if not correct_pw:
            retJson={
                "status":302,
                "msg":"incorrect password"
            }
            return jsonify(retJson)
        
        num_tokens=countTokens(username)
        if num_tokens<=0:
            retJson={
                "status":301,
                "msg":"User is out of Tokens"
            }
            return jsonify(retJson)
        
        users.update_one({
            "Username":username
        },{
            "$set":{
                "Tokens":num_tokens-1
            }
        })

        message=users.find({
            "Username":username
        })[0]["Message"]
        retJson={
            "status":200,
            "message":str(message)
        }
        return jsonify(retJson)
    
api.add_resource(Register,'/register')
api.add_resource(Store,'/store')
api.add_resource(Get, '/get')

if __name__=="__main__":
    app.run(host='0.0.0.0')