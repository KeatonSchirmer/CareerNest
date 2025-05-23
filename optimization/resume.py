import PyPDF2
import os
from ifro.app import app, user

resume_path = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{user_id}_resume.pdf")
with open(resume_path, "rb") as f:
    reader = PyPDF2.PdfReader(f)
    text = ""
    for page in reader.pages:
        text += page.extract_text()
    # Now you can use `text` for further processing