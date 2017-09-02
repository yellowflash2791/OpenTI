# OpenTI
An open source tool that can collect malicious/blacklisted ip's,domains,url's and help you export them in a csv format so that you can use it on your siem,network devices etc

Installation:

Open "requirements.txt" and pip install all the python packages
Onces all the packages are installed
execute main.py and this will fetch all the data and store it in a sqlite database TI.db,once all the data is collected,execute app.py
then you can access the gui through http://localhost:8080

