from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_jwt_extended import create_access_token
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_migrate import Migrate  # ✅ Import this
from flask import Flask, request, render_template, redirect, url_for, flash, session
from sqlalchemy.schema import UniqueConstraint


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['JWT_SECRET_KEY'] = 'super-secret-key'  # change this in real apps!



jwt = JWTManager(app)
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)  # ✅ Add this line




class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)  # ✅ Added email
    
    __table_args__ = (
        UniqueConstraint('email', name='uq_user_email'),
    )



    def __repr__(self):
        return f'<User {self.username}>'
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)

@app.route('/')
def home():
    return jsonify({"message": "Welcome to the Blog API!"})

@app.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    user_id = int(get_jwt_identity())  # Convert back to int if needed
    print(f"User ID from token: {user_id}")  # Debug log
    user = User.query.get(user_id)
    if user:
        return jsonify({
            "username": user.username,
            'email': user.email
        }), 200
    else:
        return jsonify({"message": "User not found"}), 404
    
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password') or not data.get('email'):
        return jsonify({"error": "Username, email and password are required."}), 400
    
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    if User.query.filter_by(username=username).first():
        return jsonify({'msg': 'Username already exists'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'msg': 'Email already registered'}), 400
    
    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    print(f"Received registration data: username={username}, email={email}, password={password}")

    new_user = User(username=username, password=hashed_pw, email=email)
    try:
        db.session.add(new_user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "Username or email already exists."}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500
    return jsonify({"message": "User registered successfully."}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"error": "Username and password are required."}), 400
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if user:
        if bcrypt.check_password_hash(user.password, password):
            access_token = create_access_token(identity=str(user.id))
            return jsonify(access_token=access_token), 200
        else:
            return jsonify({"error": "Invalid password."}), 401
    return jsonify({"error": "User not found."}), 404


@app.route('/logout')
def logout():
    session.pop('access_token', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


@app.route('/posts', methods=['GET', 'POST'])
@jwt_required()
def handle_posts():
    current_user = get_jwt_identity()
    if request.method == 'GET':
        posts = Post.query.all()
        result = []
        for post in posts:
            result.append({
                'id': post.id,
                'title': post.title,
                'content': post.content
            })
        return jsonify(result)
    elif request.method == 'POST':
        data = request.get_json()
        if not data or not data.get('title') or not data.get('content'):
            return jsonify({"error": "Both title and content are required."}), 400
        post = Post(title=data['title'], content=data['content'])
        db.session.add(post)
        db.session.commit()
        return jsonify({'id': post.id, 'title': post.title, 'content': post.content}), 201
    
@app.route('/posts/<int:id>', methods=['GET', 'PUT', 'DELETE'])
def handle_post_id(id):
    post = Post.query.get(id)
    if request.method == 'GET' and post:
        return jsonify({
            'id': post.id,
            'title': post.title,
            'content': post.content
        })
    elif request.method == 'PUT' and post:
        data = request.get_json()
        if not data or not data.get('title') or not data.get('content'):
            return jsonify({"error": "Both title and content are required."}), 400
        post.title = data['title']
        post.content = data['content']
        db.session.commit()
        return jsonify({
            'id': post.id,
            'title': post.title,
            'content': post.content
        })
    elif request.method == 'DELETE' and post:
        db.session.delete(post)
        db.session.commit()
        return jsonify({"message": "Post deleted successfully."})
    return {"error": "Post not found"}, 404
 
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True) 


