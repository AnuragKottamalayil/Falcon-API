import json, falcon
from sqlalchemy import create_engine, and_, or_, not_, update, delete
import hashlib
import re
import jwt
from datetime import datetime, timedelta
from jwt import ExpiredSignatureError, InvalidTokenError
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.automap import automap_base
from sqlalchemy.orm import Session, relationship


engine = create_engine('postgresql://postgres:postgres@localhost:5432/socialmedia')
Base = automap_base()
Base.prepare(engine,reflect=True)
Session = sessionmaker()
session = Session.configure(bind=engine)
User = Base.classes.users
Post = Base.classes.post
Likes = Base.classes.likes


s = Session()

def validate_positive_numbers(func):
    def wrapper(*args):
        for value in args:
            if value < 0:
                raise ValueError(“arguments must be greater than  equal zero.”)
        return func(*args)
    return wrapper

@validate_positive_numbers
def add(a, b):
    return a + b

print(add(4,4))
    


class RegisterClass:                           # User registering with details
    
    def on_post(self, req, resp):
        data = json.loads(req.stream.read())
        print('helo')
       
        context = {}
        name = data['name']
        email = data['email']
        mobile = data['mobile']
        username = data['username']
        no_hash_password = data['password']
        regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
        
        result = s.query(User).filter(User.username==username).first() # Checking for duplicate username in database
        
    

        if not result:                      # Checking password strength
            if not len(no_hash_password) >= 8 \
                and re.search("^[a-zA-Z0-9]+", no_hash_password) \
                and re.search("[a-z]+", no_hash_password) \
                and re.search("[A-Z]+", no_hash_password) \
                and re.search("[0-9]+", no_hash_password):
                print('weakpassword')
                context['response'] = 'Weakpassword'
                resp.body = json.dumps(context)
                resp.status = falcon.HTTP_404

            elif not (re.search(regex,email)):          # Validating email
                context['response'] = 'Please enter a valid email'
                resp.body = json.dumps(context)
                resp.status = falcon.HTTP_404
            else:
                encoded_password = no_hash_password.encode()
                passwrd = hashlib.sha256(encoded_password)
                password = passwrd.hexdigest()
                print(password)
                add_user = User(name=name, username=username, ph_number=mobile, password=password, email=email)
                s.add(add_user)
                s.commit()
                
                context["response"] = 'Account created successfully'
                resp.body = json.dumps(context)
                resp.status = falcon.HTTP_200
        else:
            context['response'] = 'Username already exists'
            resp.body = json.dumps(context)


class LoginClass:                           # User logging with their credentials
    
    def on_post(self, req, resp):
        context = {}
        data = json.loads(req.stream.read())
        username = data['username']
        
        no_hash_password = data['password']
        encoded_password = no_hash_password.encode()       # Generating a hashed password
        passwrd = hashlib.sha256(encoded_password)
        password = passwrd.hexdigest()    
        
        result = s.query(User).filter(and_(User.username==username, User.password==password)).first()
        print(result)
        if result:
            datas = {
                "username":username,
            }
            # Generating a jwt token if username and password are valid
            encoded_jwt_token = jwt.encode({"data":datas, "exp":datetime.utcnow() + timedelta(hours=24)}, "secret_key", algorithm="HS256")
            context['token'] = encoded_jwt_token
            context['response'] = 'Logged in'
            resp.body = json.dumps(context)
        else:
            context['response'] = "Invalid username or password"
            resp.body = json.dumps(context)


# def validate_token(func):
#     def wrapper(*args, **kwargs):
#         print('hello')
#     return wrapper


class PostCreationClass:                           # User creating a post
    @validate_token
    def on_post(self, req, resp):
        header_data = req.get_header('Authorization')
        context = {}
        try:                           # Checking that the token is valid or not
            jwt_decode = jwt.decode(header_data, key='secret_key', algorithms=['HS256'])
            print('valid token exists')
            username = jwt_decode['data']['username']
            data = json.loads(req.stream.read())
            title = data['title']
            description = data['description']
            tags = data['tags']
            result = s.query(User).filter(User.username==username).first()
            user_id = result.id
            status = 'Unpublished'
            likes = 0
            add_post= Post(title=title, description=description, tags=tags, status=status, likes=likes, user_id=user_id)
            s.add(add_post)
            s.commit()
            context['response'] = 'Post created'
            resp.body = json.dumps(context)
        except ExpiredSignatureError:
            print('signature expired')
            context['response'] = 'Signature expired Please login again'
            resp.body = json.dumps(context)
            resp.status = falcon.HTTP_404
        except InvalidTokenError:
            print('invalid token')
            context['response'] = 'Invalid token please login again'
            resp.body = json.dumps(context)
            resp.status = falcon.HTTP_404


class UserPostView:      # User viewing thier published and unpublished posts
    
    def on_post(self, req, resp):
        
        header_data = req.get_header('Authorization')
        context = {}
        li = []
        try:                           
            jwt_decode = jwt.decode(header_data, key='secret_key', algorithms=['HS256'])
            print('valid token exists')
            username = jwt_decode['data']['username']
             
            result = s.query(User).filter(User.username==username).first()
            user_id = result.id

            
            result = s.query(Post).filter(Post.user_id==user_id).all()
            for post in result:
                print(post.title)
                post_dict = {}
                post_dict['id'] = post.id
                post_dict['title'] = post.title
                post_dict['description'] = post.description
                post_dict['tags'] = post.tags
                post_dict['status'] = post.status
                post_dict['likes'] = post.likes
                li.append(post_dict)
            
            resp.body = json.dumps(li)
        except ExpiredSignatureError:
            print('signature expired')
            context['response'] = 'Signature expired Please login again'
            resp.body = json.dumps(context)
            resp.status = falcon.HTTP_404
        except InvalidTokenError:
            print('invalid token')
            context['response'] = 'Invalid token please login again'
            resp.body = json.dumps(context)
            resp.status = falcon.HTTP_404


class PublishPost:              # User publishing a created post
    
    def on_put(self, req, resp):
        header_data = req.get_header('Authorization')
        context = {}
        
        try:                           
            jwt_decode = jwt.decode(header_data, key='secret_key', algorithms=['HS256'])
            print('valid token exists')
            username = jwt_decode['data']['username']
            
            data = json.loads(req.stream.read())
            post_id = data['id']
            if post_id.isnumeric():
                result = s.query(User).filter(User.username==username).first()
                user_id = result.id
                
                
                result = s.query(Post).filter(and_(Post.id==post_id, Post.user_id==user_id)).first()
                if result:
                    result.status = 'Published'
                    s.commit()

                    context['response'] = 'Published'
                    resp.body = json.dumps(context)
                else:
                    context['response'] = 'wrong id'
                    resp.body = json.dumps(context)
            else:    
                context['response'] = 'Wrong post id'
                resp.body = json.dumps(context)
        except ExpiredSignatureError:
            print('signature expired')
            context['response'] = 'Signature expired Please login again'
            resp.body = json.dumps(context)
            resp.status = falcon.HTTP_404
        except InvalidTokenError:
            print('invalid token')
            context['response'] = 'Invalid token please login again'
            resp.body = json.dumps(context)
            resp.status = falcon.HTTP_404
            

class UnPublishPost:            # User unpublishing a published post
    def on_put(self, req, resp):
        header_data = req.get_header('Authorization')
        context = {}
        
        try:                           
            jwt_decode = jwt.decode(header_data, key='secret_key', algorithms=['HS256'])
            print('valid token exists')
            username = jwt_decode['data']['username']
            
            data = json.loads(req.stream.read())
            post_id = data['id']
            if post_id.isnumeric():
                result = s.query(User).filter(User.username==username).first()
                user_id = result.id
                
                result = s.query(Post).filter(and_(Post.id==post_id, Post.user_id==user_id)).first()
                
                if result:
                    result.status = 'Unpublished'
                    s.commit()
                
                
                    context['response'] = 'unpublished'
                    resp.body = json.dumps(context)
                else:
                    context['response'] = 'wrong id'
                    resp.body = json.dumps(context)
               
            else:
                context['response'] = 'Wrong post id'
                resp.body = json.dumps(context)
        except ExpiredSignatureError:
            print('signature expired')
            context['response'] = 'Signature expired Please login again'
            resp.body = json.dumps(context)
            resp.status = falcon.HTTP_404
        except InvalidTokenError:
            print('invalid token')
            context['response'] = 'Invalid token please login again'
            resp.body = json.dumps(context)
            resp.status = falcon.HTTP_404


class AllUsersPost:                 # User viewing posts published by other users
    
    def on_post(self, req, resp):
        header_data = req.get_header('Authorization')
        context = {}
        li = []
        
        try:                           
            jwt_decode = jwt.decode(header_data, key='secret_key', algorithms=['HS256'])
            print('valid token exists')
            username = jwt_decode['data']['username']
            result = s.query(User).filter(User.username==username).first()
            user_id = result.id
            
            
            result = s.query(Post).filter(and_(Post.user_id!=user_id, Post.status=='Published')).all()
            for post in result:
                post_dict = {}
                post_dict['id'] = post.id
                post_dict['title'] = post.title
                post_dict['description'] = post.description
                post_dict['tags'] = post.tags
                post_dict['likes'] = post.likes
                li.append(post_dict)
            context['response'] = 'published posts'
            resp.body = json.dumps(li)
        except ExpiredSignatureError:
            print('signature expired')
            context['response'] = 'Signature expired Please login again'
            resp.body = json.dumps(context)
            resp.status = falcon.HTTP_404
        except InvalidTokenError:
            print('invalid token')
            context['response'] = 'Invalid token please login again'
            resp.body = json.dumps(context)
            resp.status = falcon.HTTP_404


class LikeUnlikePost:                   
    
    def on_post(self, req, resp):
        header_data = req.get_header('Authorization')
        data = json.loads(req.stream.read())
        post_id = data['id']
        context = {}
        
        try:                           
            jwt_decode = jwt.decode(header_data, key='secret_key', algorithms=['HS256'])
            print('valid token exists')
            username = jwt_decode['data']['username']
            result = s.query(User).filter(User.username==username).first()
            user_id = result.id
            
            result = s.query(Likes).filter(and_(post_id==post_id, user_id==user_id)).first()
            if result is None:
                add_like = Likes(post_id=post_id, user_id=user_id)
                s.add(add_like)
                s.commit()
                no_of_likes = s.query(Likes).filter(Likes.post_id==post_id).count()
                post_details= s.query(Post).filter(Post.id==post_id).first()
                post_details.likes = no_of_likes
                s.commit()
                context['response'] = 'Liked'
                resp.body = json.dumps(context)
            else:
                s.delete(result)
                s.commit()
                no_of_likes = s.query(Likes).filter(Likes.post_id==post_id).count()
                post_details= s.query(Post).filter(Post.id==post_id).first()
                post_details.likes = no_of_likes
                s.commit()
                context['response'] = 'Unliked'
                resp.body = json.dumps(context)
                print('deleted')
        except ExpiredSignatureError:
            print('signature expired')
            context['response'] = 'Signature expired Please login again'
            resp.body = json.dumps(context)
            resp.status = falcon.HTTP_404
        except InvalidTokenError:
            print('invalid token')
            context['response'] = 'Invalid token please login again'
            resp.body = json.dumps(context)
            resp.status = falcon.HTTP_404



app = falcon.API()
app.add_route('/Register', RegisterClass())
app.add_route('/Login', LoginClass())
app.add_route('/CreatePost', PostCreationClass())
app.add_route('/UserPostView', UserPostView())
app.add_route('/PublishPost', PublishPost())
app.add_route('/UnpublishPost', UnPublishPost())
app.add_route('/AllUserPost', AllUsersPost())
app.add_route('/LikeUnlikePost', LikeUnlikePost())
