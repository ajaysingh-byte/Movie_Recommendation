# tmdb_client.py
import os
from typing import Optional
import requests

class TMDBException(Exception):
    pass

class TMDbClient:
    BASE_URL = 'https://api.themoviedb.org/3'
    def __init__(self, api_key: Optional[str] = None):
        api_key = api_key or os.environ.get('TMDB_API_KEY')
        if not api_key:
            raise TMDBException('TMDB_API_KEY not set. Please set TMDB_API_KEY env var or provide it to TMDbClient.')
        self.api_key = api_key
        self.session = requests.Session()
        self.session.params = {'api_key': self.api_key, 'language': 'en-US'}
        self.session.params = {'api_key': self.api_key, 'language': 'en-US'}

    def _get(self, path: str, params: Optional[dict] = None):
        url = f"{self.BASE_URL}{path}"
        try:
            resp = self.session.get(url, params=params, timeout=8)
            resp.raise_for_status()
        except requests.RequestException as e:
            raise TMDBException(str(e))
        try:
            data = resp.json()
        except ValueError:
            # Non-JSON response (HTML error page, proxy, etc.) — surface a clear message
            raise TMDBException(f"Invalid JSON response from TMDb (status={resp.status_code}): {resp.text[:300]}")
        if isinstance(data, dict) and data.get('status_code') and data.get('status_code') != 1:
            raise TMDBException(data.get('status_message', 'TMDb API error'))
        return data

    def get_genres(self):
        data = self._get('/genre/movie/list')
        return data.get('genres', [])

    def discover_movies_by_genres(self, genre_ids, sort_by='vote_average.desc', page=1, min_vote_count=50):
        if isinstance(genre_ids, (list, tuple)):
            genre_ids = ','.join(map(str, genre_ids))
        params = {
            'with_genres': str(genre_ids),
            'sort_by': sort_by,
            'page': page,
            'vote_count.gte': min_vote_count
        }
        data = self._get('/discover/movie', params=params)
        results = data.get('results', [])
        trimmed = []
        for m in results:
            trimmed.append({
                'id': m.get('id'),
                'title': m.get('title'),
                'overview': m.get('overview'),
                'release_date': m.get('release_date'),
                'poster_path': m.get('poster_path'),
                'vote_average': m.get('vote_average')
            })
        return trimmed