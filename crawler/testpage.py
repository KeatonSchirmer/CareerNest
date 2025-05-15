@app.route('/search', methods=['GET', 'POST'])
def search():
    if 'user_id' not in session:
        if request.method == 'POST':
            query = request.form.get('query')
            results = []
            if query:
                results = SearchResult.query.filter(SearchResult.job.contains(query)).all()
            return render_template('sohome.html', results=results)
        return redirect(url_for('home'))
    else: #! Have users search request check db first and then use GoogleScraper and show the results
        if request.method == 'POST':
            query = request.form.get('query')
            results = []
            if query:
                results = SearchResult.query.filter(SearchResult.job.contains(query)).all
            return render_template('search.html', results=results)
        return redirect(url_for('home'))
