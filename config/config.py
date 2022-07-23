import uuid

SECRET_KEY = uuid.uuid4().hex
DB_URI = 'sqlite:///data.db'
MAX_SIZE = 16 * 1024 * 1024
ALLOWED_EXTENSIONS = set(['docx', 'pptx', 'xlsx'])
