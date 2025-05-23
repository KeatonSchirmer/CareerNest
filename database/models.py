from database.db import db

class SearchResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    job = db.Column(db.String(250))
    company = db.Column(db.String(250))
    location = db.Column(db.String(250))
    url = db.Column(db.String(350))
    posted = db.Column(db.String(50))

def save_results_to_db(results):
    for result in results:
        exists = SearchResult.query.filter_by(
            job = result.get('job'),
            company = result.get('company'),
            url = result.get('url')
        ).first()
        if not exists:
            entry = SearchResult(
                job = result.get('job'),
                company = result.get('company'),
                location = result.get('location'),
                url = result.get('url'),
                posted = result.get('posted')
            )
            db.session.add(entry)
        db.session.commit()
    
    