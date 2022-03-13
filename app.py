#!/usr/bin/env python3
import sys
from flask import Flask, jsonify, abort, request, make_response, session
from flask_restful import reqparse, Resource, Api
from flask_session import Session
import json
from ldap3 import Server, Connection, ALL
from ldap3.core.exceptions import *
import ssl #include ssl libraries
import pymysql.cursors

import settings # Our server and db settings, stored in settings.py
import cgitb
import cgi
cgitb.enable()

app = Flask(__name__)
# Set Server-side session config: Save sessions in the local app directory.
app.secret_key = settings.SECRET_KEY
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_COOKIE_NAME'] = 'session_token'
app.config['SESSION_COOKIE_DOMAIN'] = settings.APP_HOST
Session(app)

# Error handlers
@app.errorhandler(400)  # decorators to add to 400 response
def not_found(error):
    return make_response(jsonify({"status": "Bad request"}), 400)


@app.errorhandler(404)  # decorators to add to 404 response
def not_found(error):
    return make_response(jsonify({"status": "Resource not found"}), 404)

def getDBConnetion():
    try:
        dbConnection = pymysql.connect(
                    host = settings.DB_HOST,
                    user = settings.DB_USER,
                    password = settings.DB_PASSWD,
                    db = settings.DB_DB,
                    charset='utf8mb4',
                    cursorclass= pymysql.cursors.DictCursor)
        return dbConnection
    except:
        return None

class SignIn(Resource):
    # Post (create) a session for a user and return Cookie Register a user
    # curl -i -H "Content-Type: application/json" -X POST -d '{"username": "ewoulds", "password": "7Zj*tmrh*eyZv-JKM39NaFnuqv_36N", "name": "Eric"}' -c cookie-jar -k https://cs3103.cs.unb.ca:45789/signin
    def post(self):
        #Checking for a bad request first
        if not request.json:
            abort(400)
        parser = reqparse.RequestParser()
        try:
            # Check for required attributes in json document, create a dictionary
            parser.add_argument('username', type=str, required=True)
            parser.add_argument('password', type=str, required=True)
            parser.add_argument('name', type=str, required=True)
            request_params = parser.parse_args()
        except:
            abort(400)  # bad request
        if request_params['username'] in session:
            response = {'status': 'success'}
            responseCode = 200
        else:
            try:
                ldapServer = Server(host=settings.LDAP_HOST)
                ldapConnection = Connection(ldapServer,
                    raise_exceptions=True,
                    user='uid='+request_params['username']+', ou=People,ou=fcs,o=unb',
                    password = request_params['password'])
                ldapConnection.open()
                ldapConnection.start_tls()
                ldapConnection.bind()
                # At this point we have sucessfully authenticated.
                session['username'] = request_params['username']
                response = {'status': 'success' }
                responseCode = 201
            except LDAPException:
                response = {'status': 'Access denied'}
                responseCode = 403
            finally:
                ldapConnection.unbind()
            try:
                dbConnection = pymysql.connect(
                    host = settings.DB_HOST,
                    user = settings.DB_USER,
                    password = settings.DB_PASSWD,
                    db = settings.DB_DB,
                    charset='utf8mb4',
                    cursorclass= pymysql.cursors.DictCursor)
                cursor = dbConnection.cursor()
                cursor.callproc('checkUser',(request_params['username'],))
                dbConnection.commit()
                user = cursor.fetchone()
                if user == None: #Check if user is already registered else add them to DB
                    response = {'message': "User already Registered"}
                    responseCode = 500
                else:
                    cursor = dbConnection.cursor()
                    cursor.callproc('registerUser',(request_params['username'], request_params['name']))
                    dbConnection.commit()
                    user = cursor.fetchone()
                    if user == None:
                        response = {'message': "User was not added"}
                        responseCode = 500
                    session['userId'] = user['user_id']
                dbConnection.close()
                session['userId'] = user['user_id']
            except:
                response = {'message': "Error adding user"}
                responseCode = 500

        return make_response(jsonify(response), responseCode)

    # GET: Check Cookie data with Session data
    # curl -i -H "Content-Type: application/json" -X GET -d '{"username": "ewoulds", "password": "7Zj*tmrh*eyZv-JKM39NaFnuqv_36N"}' -b cookie-jar -k https://cs3103.cs.unb.ca:45789/signin
    def get(self):
        success = False
        if 'username' in session:
            username = session['username']
            response = {'status': 'User Already Signed in '}
            responseCode = 200
        else:
            if not request.json:
                abort(400) # Missing body
            parser = reqparse.RequestParser()
            try:
                # Checking to make sure json document has all the required attributes
                parser.add_argument('username', type=str, required=True)
                parser.add_argument('password', type=str, required=True)
                request_params = parser.parse_args()
            except:
                abort(400)
            try:
                dbConnection = pymysql.connect(
                    host = settings.DB_HOST,
                    user = settings.DB_USER,
                    password = settings.DB_PASSWD,
                    db = settings.DB_DB,
                    charset='utf8mb4',
                    cursorclass= pymysql.cursors.DictCursor)
                cursor = dbConnection.cursor()
                cursor.callproc('checkUser',(request_params['username'],))
                dbConnection.commit()
                user = cursor.fetchone()
                if user == None:
                    response = {'message': "User not registered"}
                    responseCode = 500
                else:
                    try:
                        ldapServer = Server(host=settings.LDAP_HOST)
                        ldapConnection = Connection(ldapServer,
                            raise_exceptions=True,
                            user='uid='+request_params['username']+', ou=People,ou=fcs,o=unb',
                            password = request_params['password'])
                        ldapConnection.open()
                        ldapConnection.start_tls()
                        ldapConnection.bind()
                        # At this point we have sucessfully authenticated.
                        session['username'] = request_params['username']
                        response = {'status': 'success' }
                        responseCode = 201
                    except LDAPException:
                        response = {'status': 'Access denied'}
                        responseCode = 403
                    finally:
                        ldapConnection.unbind()
                dbConnection.close()
            except:
                response = {'message': "Error With DB"}
                esponseCode = 500

        return make_response(jsonify(response), responseCode)

    # DELETE: Check Cookie data with Session data
    # curl -i -H "Content-Type: application/json" -X DELETE -b cookie-jar -k https://cs3103.cs.unb.ca:45789/signin
    def delete(self):
        if 'username' in session:
            session.pop('username', None);
            response = {"status": "Successfully logout"}
            responseCode = 200
        else:
            response = {'status': 'User not in session'}
            responseCode = 401
        return make_response(jsonify(response), responseCode)

class Users(Resource):
    def get(self):
        if 'username' in session:
            try:
                dbConnection = pymysql.connect(
                    host = settings.DB_HOST,
                    user = settings.DB_USER,
                    password = settings.DB_PASSWD,
                    db = settings.DB_DB,
                    charset='utf8mb4',
                    cursorclass= pymysql.cursors.DictCursor)
                cursor = dbConnection.cursor()
                cursor.callproc('getAllUsers')
                users = cursor.fetchall()
                if users == None:
                    response = {'message': "No users Found"}
                    responseCode = 500
                return make_response(jsonify(users), 200)
            except:
                response = {'message': "Error Connecting to DB"}
                responseCode = 500
        else:
            response = {'message': 'User not signed in'}
            responseCode = 401
        
        return make_response(jsonify(response), responseCode)

class UserPresents(Resource):
    def get(self, userId):
        if not 'username' in session:
            response = {"message": "User Not signed in"}
            responseCode = 401
        else:
            if session.get('userId') != userId:
                response = {"message": "User not authorized"}
                responseCode = 401
            else:
                try:
                    dbConnection = pymysql.connect(
                        host = settings.DB_HOST,
                        user = settings.DB_USER,
                        password = settings.DB_PASSWD,
                        db = settings.DB_DB,
                        charset='utf8mb4',
                        cursorclass= pymysql.cursors.DictCursor)
                    cursor = dbConnection.cursor()
                    cursor.callproc('getUserPresentList'(usedId,))
                    presentList = cursor.fetchall()
                    dbConnection.close()
                    if presentList == None:
                        response = {'message': "unable to find any gifts"}
                        responseCode = 500
                    else:
                        return make_response(jsonify(presentList), 200)
                except:
                    response = {'message': "unable to find any gifts"}
                    responseCode = 500
        return make_response(jsonify(response), responseCode)

    def post(self, userId):
        if not request.json:
            response = {'message': 'Missing request Body'}
            responseCode = 400
        parser = reqparse.RequestParser()
        try:
            # Checking to make sure json document has all the required attributes
            parser.add_argument('name', type=str, required=True)
            parser.add_argument('cost', type=str, required=True)
            parser.add_argument('userId', type=str, required=True)
            request_params = parser.parse_args()
        except:
            abort(400)
        if not 'username' in session:
            response = {'message': 'User not logged in'}
            responseCode = 401
        else:
            if session.get('userId') != userId:
                response = {'message': 'User not Authorized'}
                responseCode = 403
            else:
                try:
                    dbConnection = pymysql.connect(
                        host = settings.DB_HOST,
                        user = settings.DB_USER,
                        password = settings.DB_PASSWD,
                        db = settings.DB_DB,
                        charset='utf8mb4',
                        cursorclass= pymysql.cursors.DictCursor)
                    cursor = dbConnection.cursor()
                    cursor.callproc('addPresent',(request_params['name'], request_params['cost'], request_params['userId']))
                    present = cursor.fetchone()
                    dbConnection.close()
                    if present == None:
                        response = {'message': "unable to create gift"}
                        responseCode = 500
                except:
                    response = {'message': "Error connecting to DB"}
                    responseCode = 500
        return make_response(jsonify(response), responseCode)

class PresentsList(Resource):
    def get(self):
        if not 'username' in session:
            response = {'message': 'User not logged in'}
            responseCode = 401
        else:
            if session.get('userId') != userId:
                response = {'message': 'User not Authorized'}
                responseCode = 403
            else:
                try:
                    dbConnection = pymysql.connect(
                        host = settings.DB_HOST,
                        user = settings.DB_USER,
                        password = settings.DB_PASSWD,
                        db = settings.DB_DB,
                        charset='utf8mb4',
                        cursorclass= pymysql.cursors.DictCursor)
                    cursor = dbConnection.cursor()
                    cursor.callproc('getMasterPresentList',(session.get('userId'),))
                    presentList = cursor.fetchall()
                    dbConnection.close()
                    if presentList == None:
                        response = {'message': "unable get presents"}
                        responseCode = 500
                    else:
                        return make_response(jsonify(presentList), 200)
                except:
                    response = {'message': "Error connecting to DB"}
                    responseCode = 500
        return make_response(jsonify(response), responseCode)

class Presents(Resource):
    def get(self, presentId):
        if not 'username' in session:
            response = {'message': 'User not logged in'}
            responseCode = 401
        else:
            try:
                dbConnection = pymysql.connect(
                    host = settings.DB_HOST,
                    user = settings.DB_USER,
                    password = settings.DB_PASSWD,
                    db = settings.DB_DB,
                    charset='utf8mb4',
                    cursorclass= pymysql.cursors.DictCursor)
                cursor = dbConnection.cursor()
                cursor.callproc('getPresentByID',(presentId,))
                present = cursor.fetchall()
                dbConnection.close()
                if present == None:
                    response = {'message': "unable get presents"}
                    responseCode = 500
                else:
                    return make_response(jsonify(present), 200)
            except:
                response = {'message': "Error connecting to DB"}
                responseCode = 500
        return make_response(jsonify(response), responseCode)
    
    def put(self, presentId):
        if not 'username' in session:
            response = {'message': 'User not logged in'}
            responseCode = 401
        else:
            try:
                dbConnection = pymysql.connect(
                    host = settings.DB_HOST,
                    user = settings.DB_USER,
                    password = settings.DB_PASSWD,
                    db = settings.DB_DB,
                    charset='utf8mb4',
                    cursorclass= pymysql.cursors.DictCursor)
                cursor = dbConnection.cursor()
                cursor.callproc('getPresentByID',(presentId,))
                present = cursor.fetchall()
                if present == None:
                    response = {'message': "unable get presents"}
                    responseCode = 500
                if present['assigned_user_id'] != -1:
                    response = {'message': "Gift is already assigned to another user"}
                    responseCode = 403
                else:
                    cursor.callproc('assignPresentToUser',(session.get('userId'), presentId))
                    dbConnection.commit()
                    present = cursor.fetchone()
                    if present == None:
                        response = {'message': "Issue assigning gift"}
                        responseCode = 500
                    else:
                        response = {'message': "Gift assigned to user"}
                        responseCode = 200
                dbConnection.close()
            except:
                response = {'message': "Error connecting to DB"}
                responseCode = 500
        return make_response(jsonify(response), responseCode)

class PresentsModify(Resource):
    def put(self, userId, presentId):
        if not request.json:
            response = {'message': 'Missing request Body'}
            responseCode = 400
        parser = reqparse.RequestParser()
        try:
            # Checking to make sure json document has all the required attributes
            parser.add_argument('name', type=str, required=True)
            parser.add_argument('cost', type=str, required=True)
            parser.add_argument('userId', type=str, required=True)
            parser.add_argument('assigned_user_id', type=int, required=True)
            request_params = parser.parse_args()
        except:
            abort(400)
        if not 'username' in session:
            response = {'message': 'User not logged in'}
            responseCode = 401
        else:
            if session.get('userId') != userId:
                response = {'message': 'User is not allowed to do this'}
                responseCode = 403
            else:
                try:
                    dbConnection = pymysql.connect(
                        host = settings.DB_HOST,
                        user = settings.DB_USER,
                        password = settings.DB_PASSWD,
                        db = settings.DB_DB,
                        charset='utf8mb4',
                        cursorclass= pymysql.cursors.DictCursor)
                    cursor = dbConnection.cursor()
                    cursor.callproc('getPresentByID',(presentId,))
                    present = cursor.fetchone()
                    if present == None:
                        response = {'message': "No Present with entered ID"}
                        responseCode = 404
                    else:
                        cursor = dbConnection.cursor()
                        cursor.callproc('updatePresent',(presentId, request_params['name'], request_params['cost'], request_params['assigned_user_id']))
                        present = cursor.fetchone()
                        if present == None:
                            response = {'message': "Error updating present"}
                            responseCode = 500
                    dbConnection.close()
                except:
                    response = {'message': "Error connecting to DB"}
                    responseCode = 500
        return make_response(jsonify(response), responseCode)

    def delete(self, userId, presenId):
        if not 'username' in session:
            response = {'message': 'User not logged in'}
            responseCode = 401
        else:
            if session.get('userId') != userId:
                response = {'message': 'User is not allowed to do this'}
                responseCode = 403
            else:
                try:
                    dbConnection = pymysql.connect(
                        host = settings.DB_HOST,
                        user = settings.DB_USER,
                        password = settings.DB_PASSWD,
                        db = settings.DB_DB,
                        charset='utf8mb4',
                        cursorclass= pymysql.cursors.DictCursor)
                    cursor = dbConnection.cursor()
                    cursor.callproc('getPresentByID',(presentId,))
                    present = cursor.fetchone()
                    if present == None:
                        response = {'message': "No Present with entered ID"}
                        responseCode = 404
                    else:
                        cursor = dbConnection.cursor()
                        cursor.callproc('removePresent')
                        present = cursor.fetchone()
                        if present == None:
                            response = {'message': "Error deleting present"}
                            responseCode = 500
                        else:
                            reponse = {'message': "deleted present"}
                            responseCode = 200
                    dbConnection.close()
                except:
                    response = {'message': "Error connecting to DB"}
                    responseCode = 500
        return make_response(jsonify(response), responseCode)

class PresentsAssigned(Resource):
    def get(self, userId):
        if not 'username' in session:
            response = {'message': 'User not logged in'}
            responseCode = 401
        else:
            if session.get('userId') != userId:
                response = {'message': 'User is not allowed to do this'}
                responseCode = 403
            else:
                try:
                    dbConnection = pymysql.connect(
                        host = settings.DB_HOST,
                        user = settings.DB_USER,
                        password = settings.DB_PASSWD,
                        db = settings.DB_DB,
                        charset='utf8mb4',
                        cursorclass= pymysql.cursors.DictCursor)
                    cursor = dbConnection.cursor()
                    cursor.callproc('getUserAssignedList',(usedId,))
                    presents = cursor.fetchall()
                    dbConnection.close()
                    if presents == None:
                        response = {'message': "no presents found"}
                        responseCode = 404
                    else:
                        return make_response(jsonify(presents), 200)
                except:
                    response = {'message': "Error connecting to DB"}
                    responseCode = 500
        return make_response(jsonify(response), responseCode)



api = Api(app)
api.add_resource(SignIn, '/signin')
api.add_resource(Users, '/users')
api.add_resource(UserPresents, '/users/<int:userId>/presents')
api.add_resource(PresentsModify, '/users/<int:userId>/presents/<int:presentId>')
api.add_resource(PresentsList, '/presents')
api.add_resource(PresentsAssigned, '/presents/<int:userId>/assignedpresents')
api.add_resource(Presents, '/presents/<int:presentId>')


if __name__ == "__main__":
    context = ('cert.pem', 'key.pem')
    app.run(
        host=settings.APP_HOST, 
        port=settings.APP_PORT, 
        ssl_context=context,
        debug=True)
