# recommendation.py
# Content-based recommender using TF-IDF on movie title + genre + description.
import threading
import pickle
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import linear_kernel

_lock = threading.Lock()

class ContentRecommender:
    def __init__(self, db_get_movies_fn):
        """
        db_get_movies_fn: callable that returns list of dicts with keys: id, title, genre, description, poster_url
        """
        self.db_get_movies_fn = db_get_movies_fn
        self._fitted = False
        self.ids = []
        self.tfidf = None
        self.vectorizer = None

    def build(self):
        with _lock:
            movies = self.db_get_movies_fn()
            corpus = []
            ids = []
            for m in movies:
                text = ' '.join(filter(None, [m.get('title',''), m.get('genre',''), m.get('description','')]))
                corpus.append(text)
                ids.append(m.get('id'))
            if not corpus:
                # nothing to build
                self.ids = []
                self.tfidf = None
                self.vectorizer = None
                self._fitted = True
                return
            self.vectorizer = TfidfVectorizer(stop_words='english', max_features=20000)
            self.tfidf = self.vectorizer.fit_transform(corpus)
            self.ids = ids
            self._fitted = True

    def ensure_built(self):
        if not self._fitted:
            self.build()

    def recommend_similar(self, movie_id, top_n=10):
        self.ensure_built()
        if not self._fitted or self.tfidf is None:
            return []
        try:
            idx = self.ids.index(movie_id)
        except ValueError:
            return []
        # use getrow() on the sparse TF-IDF matrix (csr_matrix) to avoid __getitem__ typing issues
        row_vec = self.tfidf.getrow(idx)
        cos_scores = linear_kernel(row_vec, self.tfidf).flatten()
        related_idx = cos_scores.argsort()[-(top_n+1):][::-1]
        results = []
        for i in related_idx:
            mid = self.ids[i]
            if mid == movie_id:
                continue
            results.append({'id': mid, 'score': float(cos_scores[i])})
            if len(results) >= top_n:
                break
        return results

    # Compatibility wrapper: older code calls `recommend(...)`
    def recommend(self, movie_id, top_n=10):
        return self.recommend_similar(movie_id, top_n=top_n)