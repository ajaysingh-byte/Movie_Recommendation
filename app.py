# app.py
import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
import mysql.connector
from mysql.connector import errorcode
from dotenv import load_dotenv
from tmdb_client import TMDbClient, TMDBException
from recommendation import ContentRecommender


import requests
import traceback
import secrets
from datetime import datetime, timedelta
import smtplib
from email.message import EmailMessage
from flask_mail import Mail, Message
from typing import Any, Dict, List, cast

load_dotenv()

# initialize TMDb client (requires TMDB_API_KEY env variable)
try:
    client = TMDbClient()
except Exception as _e:
    client = None
    print('TMDb client not initialized:', _e)


app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "change_me")

# Flask-Mail configuration (read from environment)
app.config.update({
    'MAIL_SERVER': os.getenv('MAIL_SERVER'),
    'MAIL_PORT': int(os.getenv('MAIL_PORT', '587')) if os.getenv('MAIL_PORT') else None,
    'MAIL_USERNAME': os.getenv('MAIL_USERNAME'),
    'MAIL_PASSWORD': os.getenv('MAIL_PASSWORD'),
    'MAIL_USE_TLS': os.getenv('MAIL_USE_TLS', 'true').lower() in ('1','true','yes'),
    'MAIL_USE_SSL': os.getenv('MAIL_USE_SSL', 'false').lower() in ('1','true','yes'),
    'MAIL_DEFAULT_SENDER': os.getenv('MAIL_DEFAULT_SENDER', 'no-reply@example.com')
})

# Initialize Flask-Mail
mail = Mail(app)

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "index"  # type: ignore

# DB helper
def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "movie_app"),
        auth_plugin="mysql_native_password"
    )

# Flask-Login User wrapper
class User(UserMixin):
    def __init__(self, id, username, email, role):
        self.id = str(id)
        self.username = username
        self.email = email
        self.role = role

    def is_admin(self):
        return self.role == "admin"

@login_manager.user_loader
def load_user(user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, username, email, role FROM users WHERE id = %s", (int(user_id),))
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        if row:
            row = cast(Dict[str, Any], row)
            return User(row["id"], row["username"], row["email"], row["role"])
    except Exception:
        # don't leak errors to user-loader, but print to console for debugging
        traceback.print_exc()
    return None

# -------------------------
# Authentication routes
# -------------------------
@app.route("/")
def index():
    # If already logged in, go straight to search page
    if current_user.is_authenticated:
        if current_user.is_admin():
            return redirect(url_for("admin_panel"))
        return redirect(url_for("search_page"))
    return render_template("index.html")

@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")

    if not username or not email or not password:
        flash("All fields are required.", "error")
        return redirect(url_for("index"))

    pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
            (username, email, pw_hash)
        )
        conn.commit()
        cursor.close()
        conn.close()
        flash("Registration successful. Please log in.", "success")
    except mysql.connector.IntegrityError as e:
        if e.errno == errorcode.ER_DUP_ENTRY:
            flash("Username or email already taken.", "error")
        else:
            flash("Database error.", "error")
    except Exception:
        traceback.print_exc()
        flash("Server error.", "error")
    return redirect(url_for("index"))

@app.route("/login", methods=["POST"])
def login():
    username_or_email = request.form.get("usernameOrEmail", "").strip()
    password = request.form.get("password", "")

    if not username_or_email or not password:
        flash("All fields are required.", "error")
        return redirect(url_for("index"))

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, username, email, password_hash, role "
            "FROM users WHERE username = %s OR email = %s LIMIT 1",
            (username_or_email, username_or_email)
        )
        row = cursor.fetchone()
        cursor.close()
        conn.close()

        row = cast(Dict[str, Any], row) if row else None

        if not row or not bcrypt.check_password_hash(row["password_hash"], password):
            flash("Invalid credentials.", "error")
            return redirect(url_for("index"))

        user = User(row["id"], row["username"], row["email"], row["role"])
        login_user(user)
        flash("Logged in successfully.", "success")

        if user.is_admin():
            return redirect(url_for("admin_panel"))
        # Normal user → SEARCH PAGE
        return redirect(url_for("search_page"))
    except Exception:
        traceback.print_exc()
        flash("Server error.", "error")
        return redirect(url_for("index"))
    
@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("Logged out.", "success")
    return redirect(url_for("index"))

# -------------------------
# User & Admin pages
# -------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.is_admin():
        return redirect(url_for("admin_panel"))
    return render_template("dashboard.html", user=current_user)

@app.route("/admin")
@login_required
def admin_panel():
    if not current_user.is_admin():
        flash("Forbidden: Admins only", "error")
        return redirect(url_for("dashboard") + "#suggestion-success")
    # Load pending suggestions to display in the admin UI
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT s.id, s.title, s.year, s.genre, s.description, s.poster_url, s.status, s.created_at,
                   u.id as user_id, u.username as suggested_by
            FROM movie_suggestions s
            JOIN users u ON s.user_id = u.id
            ORDER BY s.created_at DESC
        """)
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        suggestions = rows or []
    except Exception:
        traceback.print_exc()
        suggestions = []

    return render_template("admin.html", user=current_user, suggestions=suggestions)

# -------------------------
# API: current user
# -------------------------
@app.route("/api/me")
def api_me():
    if current_user.is_authenticated:
        return jsonify({
            "id": current_user.id,
            "username": current_user.username,
            "email": current_user.email,
            "role": current_user.role
        })
    return jsonify(None)

# -------------------------
# Admin APIs: users
# -------------------------
@app.route("/api/admin/users")
@login_required
def api_admin_users():
    if not current_user.is_admin():
        return jsonify({"error": "forbidden"}), 403
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, username, email, role, created_at FROM users ORDER BY id DESC")
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify(rows)
    except Exception:
        traceback.print_exc()
        return jsonify({"error": "server_error"}), 500

@app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
@login_required
def api_admin_delete_user(user_id):
    if not current_user.is_admin():
        return jsonify({"error": "forbidden"}), 403
    if int(current_user.id) == user_id:
        return jsonify({"error": "cannot_delete_self"}), 400
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        affected = cursor.rowcount
        cursor.close()
        conn.close()
        return jsonify({"success": True, "affected": affected})
    except Exception:
        traceback.print_exc()
        return jsonify({"error": "server_error"}), 500

# -------------------------
# Movie suggestion endpoints
# -------------------------
@app.route("/suggest", methods=["POST"])
@login_required
def suggest_movie():
    title = request.form.get("title", "").strip()
    year = request.form.get("year", "").strip()
    genre = request.form.get("genre", "").strip()
    description = request.form.get("description", "").strip()
    poster_url = request.form.get("poster_url", "").strip()

    if not title:
        flash("Title is required to suggest a movie.", "error")
        return redirect(url_for("dashboard") + "#suggestion-success")

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO movie_suggestions (user_id, title, year, genre, description, poster_url) VALUES (%s, %s, %s, %s, %s, %s)",
            (int(current_user.id), title, year or None, genre or None, description or None, poster_url or None)
        )
        conn.commit()
        cursor.close()
        conn.close()
        flash("Suggestion submitted — thank you! Admin will review it.", "success")
    except Exception:
        traceback.print_exc()
        flash("Could not submit suggestion.", "error")
    return redirect(url_for("suggest_page") + "#suggestion-success")

@app.route("/api/admin/suggestions")
@login_required
def api_admin_suggestions():
    if not current_user.is_admin():
        return jsonify({"error": "forbidden"}), 403
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT s.id, s.title, s.year, s.genre, s.description, s.poster_url, s.status, s.created_at,
                   u.id as user_id, u.username as suggested_by
            FROM movie_suggestions s
            JOIN users u ON s.user_id = u.id
            ORDER BY s.created_at DESC
        """)
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify(rows)
    except Exception:
        traceback.print_exc()
        return jsonify({"error": "server_error"}), 500

@app.route("/api/admin/suggestions/<int:suggestion_id>/approve", methods=["POST"])
@login_required
def api_admin_approve_suggestion(suggestion_id):
    if not current_user.is_admin():
        return jsonify({"error": "forbidden"}), 403
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM movie_suggestions WHERE id=%s LIMIT 1", (suggestion_id,))
        s = cursor.fetchone()
        s = cast(Dict[str, Any], s) if s else None
        if not s:
            cursor.close()
            conn.close()
            return jsonify({"error": "not_found"}), 404
        if s["status"] != "pending":
            cursor.close()
            conn.close()
            return jsonify({"error": "not_pending", "status": s["status"]}), 400

        cursor.execute(
            "INSERT INTO movies (title, year, genre, description, poster_url) VALUES (%s, %s, %s, %s, %s)",
            (s["title"], s["year"], s["genre"], s["description"], s["poster_url"])
        )
        cursor.execute("UPDATE movie_suggestions SET status='approved' WHERE id=%s", (suggestion_id,))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "server_error", "detail": str(e)}), 500

@app.route("/api/admin/suggestions/<int:suggestion_id>/reject", methods=["POST"])
@login_required
def api_admin_reject_suggestion(suggestion_id):
    if not current_user.is_admin():
        return jsonify({"error": "forbidden"}), 403
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE movie_suggestions SET status='rejected' WHERE id=%s", (suggestion_id,))
        conn.commit()
        affected = cursor.rowcount
        cursor.close()
        conn.close()
        if affected == 0:
            return jsonify({"error": "not_found"}), 404
        return jsonify({"success": True})
    except Exception:
        traceback.print_exc()
        return jsonify({"error": "server_error"}), 500

@app.route("/api/admin/suggestions/<int:suggestion_id>", methods=["DELETE"])
@login_required
def api_admin_delete_suggestion(suggestion_id):
    if not current_user.is_admin():
        return jsonify({"error": "forbidden"}), 403
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM movie_suggestions WHERE id=%s", (suggestion_id,))
        conn.commit()
        affected = cursor.rowcount
        cursor.close()
        conn.close()
        return jsonify({"success": True, "affected": affected})
    except Exception:
        traceback.print_exc()
        return jsonify({"error": "server_error"}), 500

# -------------------------
# Admin manual add movie
# -------------------------
@app.route("/admin/add_movie", methods=["POST"])
@login_required
def admin_add_movie():
    if not current_user.is_admin():
        abort(403)
    title = request.form.get("title", "").strip()
    if not title:
        flash("Title required", "error")
        return redirect(url_for("admin_panel"))
    year = request.form.get("year", "").strip()
    genre = request.form.get("genre", "").strip()
    description = request.form.get("description", "").strip()
    poster_url = request.form.get("poster_url", "").strip()
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO movies (title, year, genre, description, poster_url) VALUES (%s,%s,%s,%s,%s)",
                       (title, year or None, genre or None, description or None, poster_url or None))
        conn.commit()
        cursor.close()
        conn.close()
        flash("Movie added.", "success")
    except Exception:
        traceback.print_exc()
        flash("Could not add movie.", "error")
    return redirect(url_for("admin_panel"))

# Password reset helpers
RESET_TOKEN_TTL_HOURS = 1

def generate_token():
    return secrets.token_urlsafe(32)

def create_password_reset(email):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, email FROM users WHERE email=%s LIMIT 1", (email,))
        user = cursor.fetchone()
        user = cast(Dict[str, Any], user) if user else None
        if not user:
            cursor.close()
            conn.close()
            return None
        token = generate_token()
        expires = datetime.utcnow() + timedelta(hours=RESET_TOKEN_TTL_HOURS)
        cursor.execute("INSERT INTO password_resets (user_id, token, expires_at) VALUES (%s,%s,%s)",
                       (user['id'], token, expires))
        conn.commit()
        cursor.close()
        conn.close()
        return token
    except Exception:
        traceback.print_exc()
        return None

def send_reset_email(to_email, token):
    """
    Send reset email using Flask-Mail. If MAIL_SERVER or credentials are not configured,
    print the reset URL to the console (development fallback).
    """
    reset_url = url_for('reset_password', token=token, _external=True)
    subject = 'Password reset for Movie Recommendation System'
    body = f"Click the link to reset your password: {reset_url}\n\nIf you did not request this, ignore this email."

    # If mail isn't configured, print link to console for development/testing
    if not app.config.get('MAIL_SERVER') or not app.config.get('MAIL_USERNAME') or not app.config.get('MAIL_PASSWORD'):
        print('Password reset (dev):', reset_url)
        return

    try:
        msg = Message(subject=subject, recipients=[to_email], body=body)
        mail.send(msg)
    except Exception:
        traceback.print_exc()

# NOTE: add this table to your init_db.sql or run manually:
#
# CREATE TABLE IF NOT EXISTS password_resets (
#   id INT AUTO_INCREMENT PRIMARY KEY,
#   user_id INT NOT NULL,
#   token VARCHAR(255) NOT NULL UNIQUE,
#   expires_at DATETIME NOT NULL,
#   used TINYINT DEFAULT 0,
#   FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
# );

# Replace the existing /forgot route logic with this — it preserves the original behavior
@app.route("/forgot", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get('email')
        token = create_password_reset(email)
        if token:
            send_reset_email(email, token)
        flash("If an account with that email exists, a reset link was sent.")
        return redirect(url_for("index"))
    return render_template("forgot.html")

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT pr.id, pr.user_id, pr.expires_at, pr.used, u.email FROM password_resets pr JOIN users u ON pr.user_id=u.id WHERE pr.token=%s LIMIT 1", (token,))
        row = cursor.fetchone()
        row = cast(Dict[str, Any], row) if row else None
        if not row:
            flash('Invalid or expired reset link.', 'error')
            return redirect(url_for('index'))
        # convert expires_at from MySQL to datetime if needed
        if row['used']:
            flash('This reset link has already been used.', 'error')
            return redirect(url_for('index'))
        if row['expires_at'] < datetime.utcnow():
            flash('Reset link has expired.', 'error')
            return redirect(url_for('index'))

        if request.method == 'POST':
            password = request.form.get('password')
            password_confirm = request.form.get('password_confirm')
            if not password:
                flash('Enter a new password.', 'error')
                return render_template('reset_password.html', token=token)
            if password != password_confirm:
                flash('Passwords do not match.', 'error')
                return render_template('reset_password.html', token=token)
            pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
            cursor.execute('UPDATE users SET password_hash=%s WHERE id=%s', (pw_hash, row['user_id']))
            cursor.execute('UPDATE password_resets SET used=1 WHERE id=%s', (row['id'],))
            conn.commit()
            cursor.close()
            conn.close()
            flash('Password updated. You may now log in.', 'success')
            return redirect(url_for('index'))

        cursor.close()
        conn.close()
        return render_template('reset_password.html', token=token)
    except Exception:
        traceback.print_exc()
        flash('Server error.', 'error')
        return redirect(url_for('index'))

# -------------------------
# Movie search & recommendation pages
# -------------------------
@app.route('/api/movies/search')
@login_required
def api_movies_search():
    q = request.args.get('q', '').strip()
    if not q:
        return jsonify([])
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        like = f"%{q}%"
        cursor.execute("SELECT id, title, year, genre, poster_url FROM movies WHERE title LIKE %s OR genre LIKE %s ORDER BY title LIMIT 10", (like, like))
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify(rows)
    except Exception as e:
        traceback.print_exc()
        return jsonify([])

# TMDB API search proxy
@app.route('/api/tmdb/search')
@login_required
def api_tmdb_search():
    q = request.args.get('q', '').strip()
    if not q:
        return jsonify([])
    key = os.getenv('TMDB_API_KEY')
    if not key:
        return jsonify({'error': 'missing_api_key'}), 500
    try:
        resp = requests.get('https://api.themoviedb.org/3/search/movie', params={
            'api_key': key,
            'query': q,
            'page': 1,
            'include_adult': False
        }, timeout=5)
        data = resp.json()
        results = []
        base = 'https://image.tmdb.org/t/p/w185'
        for r in data.get('results', [])[:20]:
            results.append({
                'id': r.get('id'),
                'title': r.get('title'),
                'year': (r.get('release_date') or '')[:4],
                'poster_url': base + r['poster_path'] if r.get('poster_path') else None,
                'overview': r.get('overview')
            })
        return jsonify(results)
    except Exception as e:
        traceback.print_exc()
        return jsonify([])

# TMDB recommendations (show popular movies)
@app.route('/api/tmdb/recommendations')
@login_required
def api_tmdb_recommendations():
    key = os.getenv('TMDB_API_KEY')
    if not key:
        return jsonify({'error': 'missing_api_key'}), 500
    try:
        resp = requests.get('https://api.themoviedb.org/3/movie/popular', params={'api_key': key, 'page': 1}, timeout=5)
        data = resp.json()
        base = 'https://image.tmdb.org/t/p/w185'
        results = []
        for r in data.get('results', [])[:12]:
            results.append({
                'id': r.get('id'),
                'title': r.get('title'),
                'year': (r.get('release_date') or '')[:4],
                'poster_url': base + r['poster_path'] if r.get('poster_path') else None,
                'overview': r.get('overview')
            })
        return jsonify(results)
    except Exception:
        traceback.print_exc()
        return jsonify([])

# Page: suggest (search with TMDB + button to view user suggestions)
@app.route('/suggest_page')
@login_required
def suggest_page():
    return render_template('suggest.html', user=current_user)

# Page: user's suggestions
@app.route('/my_suggestions')
@login_required
def my_suggestions():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT id, title, year, genre, description, poster_url, status, created_at FROM movie_suggestions WHERE user_id=%s ORDER BY created_at DESC', (int(current_user.id),))
        rows = cursor.fetchall()
        rows = cast(List[Dict[str, Any]], rows) if rows else []
        cursor.close()
        conn.close()
    except Exception:
        traceback.print_exc()
        rows = []
    return render_template('my_suggestions.html', suggestions=rows, user=current_user)

# Page: search
@app.route('/search')
@login_required

def search_page():
    """
    Server-side search handler that supports your existing Jinja template.
    It reads the 'query' GET parameter, does a LIKE search on local DB,
    and passes 'movies' into the template so the server-rendered page shows results.
    """
    q = request.args.get('query', '').strip()
    movies = []
    if q:
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            like = f"%{q}%"
            cursor.execute("""
                SELECT id, title, year, genre, poster_url, rating
                FROM movies
                WHERE title LIKE %s OR genre LIKE %s
                ORDER BY title
                LIMIT 50
            """, (like, like))
            movies = cursor.fetchall()
            cursor.close()
            conn.close()
        except Exception:
            traceback.print_exc()
            movies = []

    # render server-side template with movies list (works with your existing HTML/CSS)
    return render_template('search.html', user=current_user, movies=movies, query=q)

@app.route('/recommend/genre', methods=['GET', 'POST'], endpoint='recommend_genre_tmdb')
def recommend_genre_tmdb():
    # Genre-based recommendations using TMDb discover endpoint.
    if client is None:
        flash("TMDb integration is not configured. Please set TMDB_API_KEY.", "error")
        return redirect(url_for('search_page'))

    try:
        genres = client.get_genres()
    except TMDBException as e:
        genres = []
        flash(f"Error fetching genres from TMDb: {e}", "error")

    results = []
    selected_genre_id = None
    if request.method == 'POST':
        selected_genre_id = request.form.get('genre')
        if selected_genre_id:
            try:
                results = client.discover_movies_by_genres(selected_genre_id)
                if not results:
                    flash("No movies found for that genre.", "info")
            except TMDBException as e:
                flash(f"Failed to fetch recommendations: {e}", "error")
    return render_template('recommend_genre.html', genres=genres, results=results, selected_genre_id=selected_genre_id)



# -------------------------
# Run server
# -------------------------

# --- Content-based recommender setup ---
def _get_all_movies_from_db():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, title, genre, description, poster_url, year FROM movies")
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return rows or []
    except Exception:
        return []

content_recommender = ContentRecommender(db_get_movies_fn=_get_all_movies_from_db)
# build on startup (will be quick for small DB); for large DB consider async precompute
try:
    content_recommender.build()
except Exception as _e:
    print("Content recommender build failed:", _e)
# --------------------------------------


@app.route('/recommend/content', methods=['GET','POST'], endpoint='recommend_content')
@login_required
def recommend_content():
    try:
        all_movies = _get_all_movies_from_db()
    except Exception:
        all_movies = []
    # ensure static type checker knows this is a list of dicts
    all_movies = cast(List[Dict[str, Any]], all_movies) if all_movies else []
    selected = None
    recommendations = []
    if request.method == 'POST':
        movie_id = request.form.get('movie_id')
        if movie_id:
            try:
                movie_id = int(movie_id)
                selected = movie_id
                # Try TMDb genre-based discovery first (if client configured and movie has genre)
                try:
                    conn = get_db_connection()
                    cursor = conn.cursor(dictionary=True)
                    cursor.execute('SELECT id, title, genre, description, poster_url, year FROM movies WHERE id=%s LIMIT 1', (movie_id,))
                    local_movie = cursor.fetchone()
                    local_movie = cast(Dict[str, Any], local_movie) if local_movie else None
                    cursor.close()
                    conn.close()
                except Exception:
                    traceback.print_exc()
                    local_movie = None

                used_tmdb = False
                if client is not None and local_movie and local_movie.get('genre'):
                    try:
                        # map local genre names to TMDb genre IDs
                        tmdb_genres = client.get_genres()
                        name_to_id = {g['name'].strip().lower(): g['id'] for g in tmdb_genres}
                        local_genres = [g.strip().lower() for g in (local_movie.get('genre') or '').split(',') if g.strip()]
                        genre_ids = [name_to_id[g] for g in local_genres if g in name_to_id]
                        if genre_ids:
                            tmdb_results = client.discover_movies_by_genres(genre_ids)
                            base = 'https://image.tmdb.org/t/p/w185'
                            for tr in tmdb_results:
                                recommendations.append({
                                    'movie': {
                                        'id': tr.get('id'),
                                        'title': tr.get('title'),
                                        'year': (tr.get('release_date') or '')[:4],
                                        'poster_url': base + tr['poster_path'] if tr.get('poster_path') else None,
                                        'description': tr.get('overview')
                                    },
                                    'score': tr.get('vote_average') or 0
                                })
                            used_tmdb = True
                    except Exception:
                        # TMDb failed; we'll fall back to local recommender below
                        traceback.print_exc()
                        used_tmdb = False

                if not used_tmdb:
                    # Fallback: use local content-based recommender
                    try:
                        recs = content_recommender.recommend(movie_id, top_n=20)
                        id_to = {m['id']: m for m in all_movies}
                        recommendations = [{'movie': id_to[r['id']], 'score': r['score']} for r in recs if r['id'] in id_to]
                    except Exception:
                        traceback.print_exc()
                        recommendations = []
            except Exception:
                traceback.print_exc()
    return render_template('recommend_content.html', movies=all_movies, selected=selected, recommendations=recommendations, user=current_user)

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "false").lower() in ("1", "true", "yes")
    app.run(host="127.0.0.1", port=port, debug=debug)
