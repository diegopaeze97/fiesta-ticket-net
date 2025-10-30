from flask_jwt_extended import JWTManager
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from flask_mail import Mail
from dotenv import load_dotenv
import os
import redis
from rq import Queue
import boto3
import stripe

load_dotenv()

redis_url = os.getenv('REDIS_URL')
redis_client = redis.from_url(redis_url)

# Configura Amazon s3
S3_REGION = os.getenv('S3_REGION')
AWS_ACCESS_KEY = os.getenv('AWS_ACCESS_KEY')
AWS_SECRET_KEY = os.getenv('AWS_SECRET_KEY')

s3 = boto3.client(
    "s3",
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name=S3_REGION
)

#STRIPE
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')

jwt = JWTManager()
db = SQLAlchemy()
socketio = SocketIO() #
mail = Mail()
task_queue = Queue('tasks', connection=redis_client)
