from flask import Flask, request, render_template, redirect, url_for, jsonify
import numpy as np
import pandas as pd
from sklearn import metrics
import warnings
import pickle
import sqlite3
from datetime import datetime
from convert import convertion
warnings.filterwarnings('ignore')
from feature import FeatureExtraction

# Load the model
file = open("newmodel.pkl", "rb")
gbc = pickle.load(file)
file.close()

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('phishdetector.db')
    cursor = conn.cursor()

    # Create scan_history table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        status TEXT NOT NULL,
        has_ssl INTEGER NOT NULL,
        scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Add user_email to scan_history if not present
    try:
        cursor.execute("SELECT user_email FROM scan_history LIMIT 1")
    except sqlite3.OperationalError:
        cursor.execute("ALTER TABLE scan_history ADD COLUMN user_email TEXT")

    # Create whitelist table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS whitelist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Add user_email to whitelist if not present
    try:
        cursor.execute("SELECT user_email FROM whitelist LIMIT 1")
    except sqlite3.OperationalError:
        cursor.execute("ALTER TABLE whitelist ADD COLUMN user_email TEXT")

    conn.commit()
    conn.close()


# Initialize the database on startup
init_db()

# Helper function to add a scan to history
def add_to_history(url, status, has_ssl, user_email=None):
    conn = sqlite3.connect('phishdetector.db')
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scan_history (url, status, has_ssl, user_email) VALUES (?, ?, ?, ?)",
        (url, status, has_ssl, user_email)
    )
    conn.commit()
    conn.close()

# Helper function to get scan history
def get_history(user_email=None):
    conn = sqlite3.connect('phishdetector.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    if user_email:
        cursor.execute("SELECT * FROM scan_history WHERE user_email = ? ORDER BY scan_date DESC", (user_email,))
    else:
        cursor.execute("SELECT * FROM scan_history ORDER BY scan_date DESC")
        
    history = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return history

# Helper function to remove an entry from history
def remove_from_history(id, user_email=None):
    conn = sqlite3.connect('phishdetector.db')
    cursor = conn.cursor()
    
    if user_email:
        cursor.execute("DELETE FROM scan_history WHERE id = ? AND user_email = ?", (id, user_email))
    else:
        cursor.execute("DELETE FROM scan_history WHERE id = ?", (id,))
        
    conn.commit()
    conn.close()

# Helper function to add to whitelist
def add_to_whitelist(url, user_email=None):
    conn = sqlite3.connect('phishdetector.db')
    cursor = conn.cursor()
    
    if user_email:
        cursor.execute("SELECT * FROM whitelist WHERE url = ? AND user_email = ?", (url, user_email))
    else:
        cursor.execute("SELECT * FROM whitelist WHERE url = ?", (url,))
        
    if cursor.fetchone() is None:
        cursor.execute("INSERT INTO whitelist (url, user_email) VALUES (?, ?)", (url, user_email))
        conn.commit()
        conn.close()
        return True
    conn.close()
    return False

# Helper function to get whitelist
def get_whitelist(user_email=None):
    conn = sqlite3.connect('phishdetector.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    if user_email:
        cursor.execute("SELECT * FROM whitelist WHERE user_email = ? ORDER BY date_added DESC", (user_email,))
    else:
        cursor.execute("SELECT * FROM whitelist ORDER BY date_added DESC")
        
    whitelist = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return whitelist

# Helper function to remove from whitelist
def remove_from_whitelist(id, user_email=None):
    conn = sqlite3.connect('phishdetector.db')
    cursor = conn.cursor()
    
    if user_email:
        cursor.execute("DELETE FROM whitelist WHERE id = ? AND user_email = ?", (id, user_email))
    else:
        cursor.execute("DELETE FROM whitelist WHERE id = ?", (id,))
        
    conn.commit()
    conn.close()

@app.route("/")
def home():
    return render_template("index.html")

@app.route('/result', methods=['POST', 'GET'])
def predict():
    if request.method == "POST":
        url = request.form["name"]
        user_email = request.form.get("user_email", None)
        
        obj = FeatureExtraction(url)
        x = np.array(obj.getFeaturesList()).reshape(1, 30)
        
        y_pred = gbc.predict(x)[0]
        # 1 is safe, -1 is unsafe
        
        name = convertion(url, int(y_pred))
        status = name[1] if len(name) > 1 else "unknown"
        has_ssl = 1 if len(name) > 3 and name[3] else 0

        add_to_history(url, status, has_ssl, user_email)
        return render_template("index.html", name=name)

@app.route('/history')
def history():
    user_email = request.args.get('user_email', None)
    scan_history = get_history(user_email)
    return render_template('history.html', history=scan_history)

@app.route('/remove_history/<int:id>')
def remove_history(id):
    user_email = request.args.get('user_email', None)
    remove_from_history(id, user_email)
    return redirect(url_for('history', user_email=user_email))

@app.route('/whitelist')
def whitelist():
    user_email = request.args.get('user_email', None)
    white_list = get_whitelist(user_email)
    return render_template('whitelist.html', whitelist=white_list)

@app.route('/add_whitelist', methods=['POST'])
def add_whitelist():
    url = request.form.get('url')
    user_email = request.form.get('user_email', None)
    
    if url:
        add_to_whitelist(url, user_email)
    return redirect(url_for('whitelist', user_email=user_email))

@app.route('/add_whitelist_ajax', methods=['POST'])
def add_whitelist_ajax():
    url = request.form.get('url')
    user_email = request.form.get('user_email', None)
    
    if url:
        success = add_to_whitelist(url, user_email)
        return jsonify({'success': success})
    return jsonify({'success': False})

@app.route('/remove_whitelist/<int:id>')
def remove_whitelist(id):
    user_email = request.args.get('user_email', None)
    remove_from_whitelist(id, user_email)
    return redirect(url_for('whitelist', user_email=user_email))

@app.route('/usecases', methods=['GET', 'POST'])
def usecases():
    return render_template('usecases.html')

if __name__ == "__main__":
    app.run(debug=True)