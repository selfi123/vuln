from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secure secret key

# Replace with your database setup
users_db = {}

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the username exists in the database
        if username in users_db:
            stored_hashed_password = users_db[username]

            # Check if the provided password matches the stored hashed password
            if check_password_hash(stored_hashed_password, password):
                # Store the username in the session to indicate a successful login
                session['username'] = username
                flash('Login successful!', 'success')
                return redirect(url_for('welcome'))
        
        # If username or password is incorrect, show an error message
        flash('Invalid username or password. Please try again.', 'error')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the username already exists
        if username in users_db:
            flash('Username already exists. Please choose another username.', 'error')
        else:
            # Hash the password before storing it
            hashed_password = generate_password_hash(password, method='sha256')
            users_db[username] = hashed_password
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/welcome')
def welcome():
    # Check if the user is logged in (authenticated)
    if 'username' in session:
        return f'Welcome, {session["username"]}! You are logged in.'
    return 'Welcome, Guest. Please log in.'

@app.route('/logout')
def logout():
    # Clear the user's session to log them out
    session.pop('username', None)
    return redirect(url_for('welcome'))

if __name__ == '__main__':
    app.run(debug=True)
