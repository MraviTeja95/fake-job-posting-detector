from flask import Flask,request,render_template
import joblib

model = joblib.load("../model/fake_job_model.pkl")
vectorizer = joblib.load("../model/vectorizer.pkl")

app = Flask(__name__)

@app.route("/",methods=["GET","POST"])
def home():
    if request.method=="POST":
        text = request.form["job"]
        vec = vectorizer.transform([text])
        result = model.predict(vec)[0]

        if result==1:
            prediction="Fake Job"
        else:
            prediction="Real Job"

        return render_template("index.html",prediction=prediction)

    return render_template("index.html")

app.run(debug=True)