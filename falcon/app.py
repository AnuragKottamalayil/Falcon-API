import json, falcon
import mysql.connector
import hashlib
import re
import jwt
from datetime import datetime, timedelta
from jwt import ExpiredSignatureError, InvalidTokenError


mydb = mysql.connector.connect(               # Connecting to database by mysql connector
  host="127.0.0.1",
  user="root",
  password="268724",
  database = "socialmedia"
)
mycursor = mydb.cursor()
# mycursor.execute("CREATE TABLE users (name VARCHAR(50), email VARCHAR(50), mobile BIGINT(10), username VARCHAR(50), password VARCHAR(50))")
# mycursor.execute("ALTER TABLE users ADD COLUMN id INT AUTO_INCREMENT PRIMARY KEY")
# mycursor.execute("CREATE TABLE post (id INT NOT NULL PRIMARY KEY AUTO_INCREMENT, title VARCHAR(250), description VARCHAR(250), tags TEXT(), user_id INT, FOREIGN KEY (user_id) REFERENCES users(id))")



class RegisterClass:                           # User registering with details
    
    def on_post(self, req, resp):
        data = json.loads(req.stream.read())
        print('helo')
        sql = "INSERT INTO users (name, email, mobile, username, password) VALUES (%s, %s, %s, %s, %s)"
        context = {}
        name = data['name']
        email = data['email']
        mobile = data['mobile']
        username = data['username']
        no_hash_password = data['password']
        regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
        mycursor.execute("SELECT username FROM users WHERE username = '%s'" % username) # Checking for duplicate username in database
        result = mycursor.fetchone()

        if result is None:                      # Checking password strength
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
                val = (name, email, mobile, username, password)
                mycursor.execute(sql, val)

                mydb.commit()
                print(mycursor.rowcount, "record inserted.")
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
        
        mycursor.execute("SELECT username, password FROM USERS WHERE username='%s' AND password='%s'" % (username, password))
        result = mycursor.fetchone()
        print("result", result)
        if result is not None:
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


class PostCreationClass:                           # User creating a post
    
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
            mycursor.execute("SELECT id FROM users WHERE username = '%s'" % username)
            id = mycursor.fetchone()
            user_id = id[0]
            status = 'Unpublished'
            likes = 0
            sql ="INSERT INTO post (title, description, tags, user_id, status, likes) VALUES (%s, %s, %s, %s, %s, %s)"
            val = (title, description, tags, user_id, status, likes)
            mycursor.execute(sql, val)
            mydb.commit()
            print(mycursor.rowcount, "record inserted.")
            print(mycursor)
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
             
            mycursor.execute("SELECT id FROM users WHERE username = '%s'" % username)
            id = mycursor.fetchone()
            user_id = id[0]
            mycursor.execute("SELECT * FROM post WHERE user_id='%s'" % user_id)
            for post in mycursor:
                post_dict = {}
                post_dict['id'] = post[0]
                post_dict['title'] = post[1]
                post_dict['description'] = post[2]
                post_dict['tags'] = post[3]
                post_dict['status'] = post[5]
                post_dict['likes'] = post[6]
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
                mycursor.execute("SELECT id FROM users WHERE username = '%s'" % username)
                id = mycursor.fetchone()
                user_id = id[0]
                
                mycursor.execute("UPDATE post SET status='%s' WHERE id='%s' AND user_id='%s'" % ('Published', post_id, user_id))
                mydb.commit()
                
                print(mycursor.rowcount, 'row updated')
                if mycursor.rowcount == 1:
                    context['response'] = 'Post published'
                    resp.body = json.dumps(context)
                else:
                    context['response'] = 'not updated'
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
                mycursor.execute("SELECT id FROM users WHERE username = '%s'" % username)
                id = mycursor.fetchone()
                user_id = id[0]
                
                mycursor.execute("UPDATE post SET status='%s' WHERE id='%s' AND user_id='%s'" % ('Unublished', post_id, user_id))
                mydb.commit()
                
                print(mycursor.rowcount, 'row updated')
                if mycursor.rowcount == 1:
                    context['response'] = 'Post Unpublished'
                    resp.body = json.dumps(context)
                else:
                    context['response'] = 'not updated'
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
            mycursor.execute("SELECT id FROM users WHERE username = '%s'" % username)
            id = mycursor.fetchone()
            user_id = id[0]
            
            mycursor.execute("SELECT * FROM POST WHERE user_id !='%s' AND status='Published'" % user_id)
            for post in mycursor:
                post_dict = {}
                post_dict['id'] = post[0]
                post_dict['title'] = post[1]
                post_dict['description'] = post[2]
                post_dict['tags'] = post[3]
                post_dict['likes'] = post[6]
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
            mycursor.execute("SELECT id FROM users WHERE username = '%s'" % username)
            id = mycursor.fetchone()
            user_id = id[0]
            mycursor.execute("SELECT post_id FROM likes WHERE post_id='%s' AND user_id='%s'" % (post_id, user_id))
            result = mycursor.fetchone()
            if result is None:
                sql ="INSERT INTO likes (post_id, user_id) VALUES (%s, %s)"
                val = (post_id, user_id)
                mycursor.execute(sql, val)
                mydb.commit()
                mycursor.execute("SELECT COUNT(*) FROM likes WHERE post_id='%s'" % post_id)
                rows = mycursor.fetchone()
                no_of_likes = rows[0]
                sql = ("UPDATE post SET likes='%s' WHERE id='%s'" % (no_of_likes, post_id))
                
                mycursor.execute(sql)
                mydb.commit()
                context['response'] = 'liked'
                resp.body = json.dumps(context)
            else:
                
                mycursor.execute("DELETE FROM likes WHERE post_id='%s' AND user_id='%s'" % (post_id, user_id))
                mydb.commit()
                mycursor.execute("SELECT COUNT(*) FROM likes WHERE post_id='%s'" % post_id)
                rows = mycursor.fetchone()
                no_of_likes = rows[0]
                sql = ("UPDATE post SET likes='%s' WHERE id='%s'" % (no_of_likes, post_id))
                
                mycursor.execute(sql)
                mydb.commit()
    
                context['response'] = 'Unliked'
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



app = falcon.API()
app.add_route('/Register', RegisterClass())
app.add_route('/Login', LoginClass())
app.add_route('/CreatePost', PostCreationClass())
app.add_route('/UserPostView', UserPostView())
app.add_route('/PublishPost', PublishPost())
app.add_route('/UnpublishPost', UnPublishPost())
app.add_route('/AllUserPost', AllUsersPost())
app.add_route('/LikeUnlikePost', LikeUnlikePost())
