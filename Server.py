from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def dashboard():
    print("Dashboard accessed")
    return render_template('dashboard.html')

if __name__ == '__main__':
    port = 7440 
    app.run(debug=True, port=port, host='0.0.0.0', use_reloader=False)