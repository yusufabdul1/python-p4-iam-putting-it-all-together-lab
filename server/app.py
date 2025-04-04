#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return {'error': 'Username and password required'}, 422
            
        try:
            user = User(
                username=username,
                bio=data.get('bio'),
                image_url=data.get('image_url')
            )
            user.password_hash = password
            db.session.add(user)
            db.session.commit()
            
            session['user_id'] = user.id
            return user.to_dict(), 201
            
        except IntegrityError:
            return {'error': 'Username already exists'}, 422

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Unauthorized'}, 401
            
        user = User.query.filter_by(id=user_id).first()
        if not user:
            return {'error': 'Unauthorized'}, 401
            
        return user.to_dict(), 200

class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return {'error': 'Username and password required'}, 401
            
        user = User.query.filter_by(username=username).first()
        if not user or not user.authenticate(password):
            return {'error': 'Invalid credentials'}, 401
            
        session['user_id'] = user.id
        return user.to_dict(), 200

class Logout(Resource):
    def delete(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Unauthorized'}, 401
            
        session.pop('user_id', None)
        return {}, 204

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Unauthorized'}, 401
            
        user = User.query.filter_by(id=user_id).first()
        if not user:
            return {'error': 'Unauthorized'}, 401
            
        recipes = [recipe.to_dict() for recipe in user.recipes]
        return recipes, 200
        
    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Unauthorized'}, 401
            
        data = request.get_json()
        try:
            recipe = Recipe(
                title=data['title'],
                instructions=data['instructions'],
                minutes_to_complete=data['minutes_to_complete'],
                user_id=user_id
            )
            
            db.session.add(recipe)
            db.session.commit()
            return recipe.to_dict(), 201
            
        except (KeyError, IntegrityError, ValueError) as e:
            if "Instructions must be at least 50 characters" in str(e):
                return {'error': 'Instructions must be at least 50 characters'}, 422
            return {'error': 'Invalid recipe data'}, 422

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)