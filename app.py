from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash
from database.db import db
from database.models import SearchResult, save_results_to_db
from apscheduler.schedulers.background import BackgroundScheduler
from crawler.crawler import LinkedInScraper, GoogleScraper
import os
from werkzeug.utils import secure_filename




app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://ifro_user:Thunder1589@localhost/ifro_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

app.secret_key = 'schirmer_czubaj'

UPLOAD_FOLDER =os.path.join(os.getcwd(), 'uploads')
ALLOWED_EXTENSIONS = {'pdf'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'keasch1589@gmail.com'
app.config['MAIL_PASSWORD'] = 'otit atoy kjjn knta'
mail = Mail(app)

s = URLSafeTimedSerializer(app.secret_key)

@app.context_processor
def inject_logged_in():
    return dict(logged_in=('user_id' in session))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

#* Home Page

@app.route('/', methods=['GET'])
def home():
    results = SearchResult.query.order_by(SearchResult.id.desc()).limit(24).all()
    if not session.get('username'):
        return render_template('sohome.html', results=results)
    else:
        user = User.query.get(session['user_id'])
        return render_template('sihome.html',results=results, user=user)

#* Login Settings

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(120), nullable=False)
    last_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    degree = db.Column(db.String(120), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    resume_filename = db.Column(db.String(200))
    
    def __repr__(self):
        return f'<User {self.username}>'

@app.route('/auth', methods=['GET', 'POST'])
def login():

    form_type = 'login'
    if request.method == 'POST':
        form_type = request.form.get('form_type')


        if form_type == 'login':
            # Logic for login
            username = request.form['username']
            password = request.form['password']

            user = User.query.filter_by(username=username).first()
            if user and check_password_hash(user.password, password):
                session["username"] = user.username
                session['user_id'] = user.id
                return redirect(url_for('home'))
            else:
                error = 'Invalid username or password'
                return render_template('auth.html', error=error, form_type='login') #* Currently it is not displaying error message

        elif form_type == 'register':
            username = request.form['username']
            password = request.form['password']
            first_name = request.form['first_name']
            last_name = request.form['last_name']
            email = request.form['email']
            degree = request.form['degree']
            address = request.form['address']

            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                error = 'Username Taken'
                return render_template('auth.html', error=error, form_type='register')
            
            hashed_password = generate_password_hash(password, method='scrypt')
            new_user = User(
                first_name=first_name,
                last_name=last_name,
                username=username, 
                password=hashed_password,
                email=email,
                degree=degree,
                address=address
                )
            db.session.add(new_user)
            db.session.commit()
            session['username'] = new_user.username
            session['user_id'] = new_user.id

            return redirect(url_for('profile'))
        
    return render_template('auth.html', form_type=form_type)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

#* Password Settings

@app.route('/change_password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']
    if not check_password_hash(user.password, current_password):
        password_message = "Current password is incorrect."
    elif new_password != confirm_password:
        password_message = "New passwords do not match."
    else:
        user.password = generate_password_hash(new_password)
        db.session.commit()
        password_message = "Password changed successfully."
    # Render profile page with message (ensure you pass password_message to template)
    return redirect(url_for('profile', password_message=password_message))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(user.email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('Password Reset Request',
                          sender=app.config['MAIL_USERNAME'],
                          recipients=[user.email])
            msg.body = f'Click the link to reset your password: {reset_url}'
            mail.send(msg)
            message = "Password reset instructions sent to your email."
        else:
            message = "Email not found."
        return render_template('forgot_password.html', message=message)
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)  # 1 hour expiration
    except Exception:
        return "The reset link is invalid or has expired."
    if request.method == 'POST':
        new_password = request.form['new_password']
        user = User.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(new_password)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template('reset_password.html')

#* User Profile

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if user:
        return render_template('profile.html', user=user)
    else:
        redirect(url_for('login'))

@app.route('/edit_profile', methods=['POST'])
def edit_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if user:
        user.first_name = request.form['first_name']
        user.last_name = request.form['last_name']
        user.email = request.form['email']
        user.degree = request.form['degree']
        user.address = request.form['address']
        user.username = request.form['username']
        db.session.commit()
        edit_message = "Profile updated successfully."
        return redirect(url_for('profile', edit_message=edit_message))
    else:
        return "User not found", 404
    
@app.route('/upload_resume', methods=['GET', 'POST'])
def upload_resume():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        if 'resume' not in request.files:
            return "No file part", 400
        file = request.files['resume']
        if file.filename == '':
            return "No selected file", 400
        if file and allowed_file(file.filename):
            filename = secure_filename(f"user_{session['user_id']}_resume.pdf")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            user.resume_filename = filename
            db.session.commit()
            return redirect(url_for('profile', tab='resume'))
        else:
            return "Invalid file type. Only PDF allowed.", 400
    return render_template('upload_resume.html')

@app.route('/resume/<int:user_id>')
def view_resume(user_id):
    user = User.query.get(user_id)
    if user and user.resume_filename:
        resume_path = os.path.join(app.config['UPLOAD_FOLDER'], user.resume_filename)
        if os.path.exists(resume_path):
            return send_from_directory(app.config['UPLOAD_FOLDER'], user.resume_filename)
    else:
        return "Resume not found.", 404

#* Search
    
@app.route('/search', methods=['GET', 'POST'])
def search():
    page = int(request.args.get('page', 1))
    per_page = 10 #! Add location search feature
    db_results = []
    total_db_results = 0
    if request.method == 'POST':
        query = request.form.get('query', '').strip()
    else:
        query = request.args.get('query', '').strip()
    google_results = []
    user = None

    if 'user_id' in session:
        user = User.query.get(session['user_id'])

    show_db = request.values.get('show_db', '1') == '1'
    show_companies = request.values.get('show_companies', '1') == '1'
    show_requirements = request.values.get('show_requirements', '1') == '1'
    show_ideal = request.values.get('show_ideal', '1') == '1'


    if query:
        pagination = SearchResult.query.filter(
            (SearchResult.job.ilike(f"%{query}%")) |
            (SearchResult.company.ilike(f"%{query}%")) |
            (SearchResult.location.ilike(f"%{query}%"))
        ).paginate(page=page, per_page=per_page, error_out=False)
        db_results = pagination.items
        total_db_results = pagination.total

        print(f"GoogleScraper called with query: '{query}'")

        google_results = GoogleScraper.search_api(
            user_query=query,
            total_results=per_page,
            params={
                'key': 'AIzaSyDRev_yjHadZmkCkxqYP8Y4XzxEahLp1gA',
                'cx': '23c933d7a0f4840b0',
                'q': query,
                'start': 40 + (page - 1) * per_page
            },
            url='https://customsearch.googleapis.com/customsearch/v1',
            ignore_keywords=['linkedin', 'indeed', 'wikipedia'],
            results_per_page=per_page
        )

        for result in google_results:
            exists = SearchResult.query.filter_by(
                job = result.get('title'),
                company = '',
                url = result.get('link')
            ).first()
            if not exists:
                new_result = SearchResult(
                    job = result.get('title'),
                    company = '', 
                    location = '',
                    url = result.get('link')
                )
                db.session.add(new_result)
            db.session.commit()

    return render_template(
        'search.html', 
        db_results=db_results, 
        google_results=google_results, 
        query=query,
        user=user,
        page=page,
        total_db_results=total_db_results,
        per_page=per_page,
        pagination=pagination if query else None,
        show_db=show_db,
        show_companies=show_companies,
        show_requirements=show_requirements,
        show_ideal=show_ideal
        )

#* Message

@app.route('/message', methods=['GET', 'POST'])
def message():
    try:
        if 'user_id' not in session:
            return redirect(url_for('login'))

        user_id = session['user_id']        
        user = User.query.filter_by(id=user_id).first()

        if not user:
            return 'User not found', 404
        
        return render_template('message.html', user=user)
    except Exception as e:
        app.logger.error(f'Error in /message route: {e}')
        return 'An error occured while fetching messages'


#* Application

@app.route('/application', methods=['GET', 'POST'])
def application():
    try:
        if'user_id' not in session:
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])

        if user:
            return render_template('application.html', user=user)
        else:
            redirect(url_for('login'))
        
    except Exception as e:
        app.logger.error(f'Error in /application route: {e}')
        return 'An error occured'

#* History

@app.route('/history', methods=['GET', 'POST'])
def history():
    # Logic to fetch and display user's history
    return render_template('history.html')

def run_crawler():
    with app.app_context():
        print("Running LinkedIn Crawler...")
        infos = LinkedInScraper.l_listings(LinkedInScraper.soup_l)
        save_results_to_db(infos)
        print(f'Saved {len(infos)} new results to the database')

scheduler = BackgroundScheduler()
scheduler.add_job(run_crawler, 'interval', hours=3)
scheduler.start()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print(SearchResult.query.all())
        run_crawler()
    app.run(debug=True)