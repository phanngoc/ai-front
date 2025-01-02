from flask import Flask, request, jsonify, session
from langchain import LangChain
from langchain.prompts import PromptTemplate
from langchain.models import OpenAI
import uuid
import requests
import os
from werkzeug.utils import secure_filename
from peewee import Model, CharField, TextField, DateTimeField, BooleanField, SqliteDatabase
import datetime
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.secret_key = 'supersecretkey'
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
langchain = LangChain()
UPLOAD_FOLDER = 'public/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Initialize Peewee database
db = SqliteDatabase('database.db')

class BaseModel(Model):
    class Meta:
        database = db

class User(UserMixin, BaseModel):
    id = CharField(primary_key=True)
    email = CharField(unique=True)
    password = CharField()

class Document(BaseModel):
    id = CharField(primary_key=True)
    title = CharField()
    content = TextField()
    kind = CharField()
    user_id = CharField()

class Chat(BaseModel):
    id = CharField(primary_key=True)
    created_at = DateTimeField(default=datetime.datetime.now)
    user_id = CharField()
    title = CharField()
    visibility = BooleanField(default=True)

class Message(BaseModel):
    id = CharField(primary_key=True)
    chat_id = CharField()
    role = CharField()
    content = TextField()
    created_at = DateTimeField()

class Suggestion(BaseModel):
    id = CharField(primary_key=True)
    document_id = CharField()
    original_text = TextField()
    suggested_text = TextField()
    description = TextField()
    is_resolved = BooleanField()
    user_id = CharField()
    created_at = DateTimeField()
    document_created_at = DateTimeField()

db.connect()
db.create_tables([User, Document, Chat, Message, Suggestion])

@login_manager.user_loader
def load_user(user_id):
    return User.get_or_none(User.id == user_id)

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'error': 'Missing email or password'}), 400
    if User.get_or_none(User.email == email):
        return jsonify({'error': 'User already exists'}), 400
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User.create(id=str(uuid.uuid4()), email=email, password=hashed_password)
    login_user(user)
    return jsonify({'message': 'User registered successfully'}), 200

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    user = User.get_or_none(User.email == email)
    if user and bcrypt.check_password_hash(user.password, password):
        login_user(user)
        return jsonify({'message': 'Logged in successfully'}), 200
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'}), 200

# Define the tools
def get_weather(latitude, longitude):
    response = requests.get(
        f"https://api.open-meteo.com/v1/forecast?latitude={latitude}&longitude={longitude}&current=temperature_2m&hourly=temperature_2m&daily=sunrise,sunset&timezone=auto"
    )
    return response.json()

def create_document(title, kind):
    id = str(uuid.uuid4())
    draft_text = ""
    if kind == "text":
        prompt = PromptTemplate(
            input_variables=["title"],
            template="Write about the given topic. Markdown is supported. Use headings wherever appropriate."
        )
        model = OpenAI(model="text-davinci-003")
        draft_text = model(prompt.format(title=title))
    elif kind == "code":
        prompt = PromptTemplate(
            input_variables=["title"],
            template="Write code for the given topic."
        )
        model = OpenAI(model="code-davinci-002")
        draft_text = model(prompt.format(title=title))
    return {"id": id, "title": title, "kind": kind, "content": draft_text}

def update_document(id, description):
    document = Document.get_or_none(Document.id == id)
    if document:
        document.content = description
        document.save()
        return {"id": id, "description": description, "content": "Updated content"}
    return {"error": "Document not found"}

def request_suggestions(document_id):
    document = Document.get_or_none(Document.id == document_id)
    if document:
        # Placeholder for generating suggestions
        return {"document_id": document_id, "suggestions": ["Suggestion 1", "Suggestion 2"]}
    return {"error": "Document not found"}

@app.route('/api/chat', methods=['POST'])
@login_required
def handle_chat():
    data = request.json
    user_message_id = str(uuid.uuid4())
    response_data = {
        "type": "user-message-id",
        "content": user_message_id
    }
    # Handle the tools execution
    tool = data.get("tool")
    if tool == "getWeather":
        result = get_weather(data["latitude"], data["longitude"])
    elif tool == "createDocument":
        result = create_document(data["title"], data["kind"])
    elif tool == "updateDocument":
        result = update_document(data["id"], data["description"])
    elif tool == "requestSuggestions":
        result = request_suggestions(data["documentId"])
    else:
        result = {"error": "Invalid tool"}
    
    # Save the chat message in the database
    chat_id = data.get("chatId")
    user_id = data.get("userId")
    message_content = data.get("message")
    if chat_id and user_id and message_content:
        Message.create(
            id=user_message_id,
            chat_id=chat_id,
            role="user",
            content=message_content,
            created_at=datetime.datetime.now()
        )
    
    response_data["result"] = result
    return jsonify(response_data)

@app.route('/api/suggestions', methods=['GET'])
@login_required
def get_suggestions():
    document_id = request.args.get('documentId')

    if not document_id:
        return jsonify({'error': 'Not Found'}), 404

    # Placeholder for authentication
    session = {'user': {'id': 'user_id'}}

    if not session or not session.get('user'):
        return jsonify({'error': 'Unauthorized'}), 401

    suggestions = Suggestion.select().where(Suggestion.document_id == document_id)

    if not suggestions:
        return jsonify([]), 200

    suggestion = suggestions[0]

    if suggestion.user_id != session['user']['id']:
        return jsonify({'error': 'Unauthorized'}), 401

    return jsonify([s.__data__ for s in suggestions]), 200

@app.route('/api/history', methods=['GET'])
@login_required
def get_history():
    # Placeholder for authentication
    session = {'user': {'id': 'user_id'}}

    if not session or not session.get('user'):
        return jsonify({'error': 'Unauthorized'}), 401

    chats = Chat.select().where(Chat.user_id == session['user']['id'])

    return jsonify([chat.__data__ for chat in chats]), 200

@app.route('/api/files/upload', methods=['POST'])
@login_required
def upload_file():
    # Placeholder for authentication
    session = {'user': {'id': 'user_id'}}

    if not session:
        return jsonify({'error': 'Unauthorized'}), 401

    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return jsonify({'message': 'File uploaded successfully', 'url': f'/uploads/{filename}', 'name': filename, 'contentType': file.content_type}), 200

@app.route('/api/document', methods=['GET'])
@login_required
def get_document():
    document_id = request.args.get('id')

    if not document_id:
        return jsonify({'error': 'Missing id'}), 400

    # Placeholder for authentication
    session = {'user': {'id': 'user_id'}}

    if not session or not session.get('user'):
        return jsonify({'error': 'Unauthorized'}), 401

    document = Document.get_or_none(Document.id == document_id)

    if not document:
        return jsonify({'error': 'Not Found'}), 404

    if document.user_id != session['user']['id']:
        return jsonify({'error': 'Unauthorized'}), 401

    return jsonify(document.__data__), 200

@app.route('/api/document', methods=['POST'])
@login_required
def save_document():
    document_id = request.args.get('id')

    if not document_id:
        return jsonify({'error': 'Missing id'}), 400

    # Placeholder for authentication
    session = {'user': {'id': 'user_id'}}

    if not session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json
    content = data.get('content')
    title = data.get('title')
    kind = data.get('kind')

    document, created = Document.get_or_create(id=document_id, defaults={
        'content': content,
        'title': title,
        'kind': kind,
        'user_id': session['user']['id']
    })

    if not created:
        document.content = content
        document.title = title
        document.kind = kind
        document.save()

    return jsonify(document.__data__), 200

@app.route('/api/document', methods=['PATCH'])
@login_required
def update_document():
    document_id = request.args.get('id')
    timestamp = request.json.get('timestamp')

    if not document_id:
        return jsonify({'error': 'Missing id'}), 400

    # Placeholder for authentication
    session = {'user': {'id': 'user_id'}}

    if not session or not session.get('user'):
        return jsonify({'error': 'Unauthorized'}), 401

    document = Document.get_or_none(Document.id == document_id)

    if document.user_id != session['user']['id']:
        return jsonify({'error': 'Unauthorized'}), 401

    # Placeholder for deleting documents by id after timestamp
    return jsonify({'message': 'Deleted'}), 200

@app.route('/api/actions/saveModelId', methods=['POST'])
@login_required
def save_model_id():
    model = request.json.get('model')
    # Placeholder for saving model id in cookies
    return jsonify({'message': 'Model id saved'}), 200

@app.route('/api/actions/generateTitleFromUserMessage', methods=['POST'])
@login_required
def generate_title_from_user_message():
    message = request.json.get('message')
    # Placeholder for generating title from user message
    title = "Generated Title"
    return jsonify({'title': title}), 200

@app.route('/api/actions/deleteTrailingMessages', methods=['POST'])
@login_required
def delete_trailing_messages():
    message_id = request.json.get('id')
    # Placeholder for deleting trailing messages
    return jsonify({'message': 'Trailing messages deleted'}), 200

@app.route('/api/actions/updateChatVisibility', methods=['POST'])
@login_required
def update_chat_visibility():
    chat_id = request.json.get('chatId')
    visibility = request.json.get('visibility')
    # Placeholder for updating chat visibility
    return jsonify({'message': 'Chat visibility updated'}), 200

if __name__ == '__main__':
    app.run(debug=True)
