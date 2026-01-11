# 🎬 Movie Recommendation Web Application

A Flask-based Movie Recommendation System that allows users to explore movies, get personalized recommendations, and manage user authentication. The application uses the **TMDB API** for movie data and **MySQL** for storing user and application data.

---

## 📌 Features

- 🔐 User Authentication (Login / Logout)
- 👤 Admin creation and management
- 🎥 Movie browsing using TMDB API
- ⭐ Personalized movie recommendations
- 🔍 Search movies by title
- 🗄️ MySQL database integration
- 📱 Responsive UI using HTML, CSS, and JavaScript

---

## 🛠️ Tech Stack

### Frontend
- HTML5  
- CSS3  
- JavaScript  

### Backend
- Python (Flask)
- Flask-Login
- Flask-Bcrypt

### Database
- MySQL

### API
- TMDB (The Movie Database) API

---

## 📂 Project Structure

```text
movie_app/
│
├── app.py                  # Main Flask application
├── recommendation.py       # Movie recommendation logic
├── tmdb_client.py          # TMDB API integration
├── create_admin.py         # Admin creation script
├── .env                    # Environment variables
│
├── templates/
│   └── index.html          # Main HTML template
│
├── static/
│   ├── css/                # Stylesheets
│   ├── js/                 # JavaScript files
│   └── images/             # Images and assets
│
└── __pycache__/            # Python cache files
```
---

## ⚙️ Environment Variables

Create a `.env` file in the root directory and add:

FLASK_SECRET_KEY=your_secret_key
TMDB_API_KEY=your_tmdb_api_key
DB_HOST=localhost
DB_USER=your_mysql_username
DB_PASSWORD=your_mysql_password
DB_NAME=movie_db


---

## 🚀 How to Run the Project Locally

### 1️⃣ Clone the Repository

- git clone https://github.com/your-username/movie-recommendation-app.git
- cd movie-recommendation-app

### 2️⃣ Create a Virtual Environment (Optional but Recommended)

- python -m venv venv
- source venv/bin/activate   *# For Linux/Mac*
- venv\Scripts\activate      *# For Windows*

### 3️⃣ Install Dependencies

- pip install flask flask-login flask-bcrypt mysql-connector-python python-dotenv

### 4️⃣ Set Up MySQL Database

- Create a database in MySQL
- Update database credentials in .env

### 5️⃣ Create Admin User
- python create_admin.py

### 6️⃣ Run the Application
- python app.py

### 7️⃣ Open in Browser
- http://127.0.0.1:5000/

# 👨‍💻 Author
- Ajay Singh
- MCA Student | Software Developer