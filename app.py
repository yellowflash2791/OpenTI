from flask import Flask, render_template,request,url_for,Response
import sqlite3 as sql
import csv
import flask_excel

app = Flask(__name__,template_folder='templates',static_folder='templates/js')
app.jinja_env.add_extension("chartkick.ext.charts")

@app.route('/search')
def form_web():
   return render_template("search.html") 

@app.route('/result',methods=['POST'])
def search():
    s=request.form['search']
    v = request.form['threats']
    con = sql.connect("TI.db")
    con.row_factory = sql.Row
    cur = con.cursor()
    if v=='IP':
       cur.execute("select * from IP where ip like ? or threat like ? or threat_info like ?  ",('%'+s+'%','%'+s+'%','%'+s+'%'))
#        cur.execute("select * from IP where threat like '%spam%'  ") 

    if v=='Domain':
       cur.execute("select * from Domain where domain like ? or threat like ? or threat_info like ?  ",('%'+s+'%','%'+s+'%','%'+s+'%'))        

    if v=='URL':
       cur.execute("select * from URL where url like ? or threat like ? or threat_info like ?  ",('%'+s+'%','%'+s+'%','%'+s+'%'))  
    if v=='ti':
       cur.execute("select * from ti where data like ? or threat like ? or threat_info like ?  ",('%'+s+'%','%'+s+'%','%'+s+'%'))
    if not s:
       cur.execute("select * from '%s' " %v) 
    rows = cur.fetchall();
  
    
    return render_template("result.html",rows=rows,s=s,v=v)

@app.route('/export',methods=['POST'])
def export():
    s=request.form['string']
    v=request.form['option']
    con = sql.connect("TI.db")
    con.row_factory = sql.Row
    cur = con.cursor()
    if v=='IP':
       cur.execute("select ip,threat,threat_info from IP where ip like ? or threat like ? or threat_info like ?  ",('%'+s+'%','%'+s+'%','%'+s+'%'))
#        cur.execute("select * from IP where threat like '%spam%'  ") 

    if v=='Domain':
       cur.execute("select domain,threat,threat_info from Domain where domain like ? or threat like ? or threat_info like ?  ",('%'+s+'%','%'+s+'%','%'+s+'%'))

    if v=='URL':
       cur.execute("select url,threat,threat_info from URL where url like ? or threat like ? or threat_info like ?  ",('%'+s+'%','%'+s+'%','%'+s+'%'))
    if v=='ti':
        cur.execute("select data,threat,threat_info from ti where data like ? or threat like ? or threat_info like ?  ",('%'+s+'%','%'+s+'%','%'+s+'%'))
    if not s:
       cur.execute("select * from '%s' " %v)
    rows = cur.fetchall()

    return flask_excel.make_response_from_array(rows, "csv", file_name="data.csv")
@app.route('/threat')
def Threat():

     l={}
     r=[]
     d=[]
     con = sql.connect("TI.db")
     c = con.cursor()

     c.execute("SELECT threat FROM ti group by threat ")
     d=[i[0] for i in c.fetchall()]

     c.execute("SELECT count(threat) FROM ti group by threat")
     e=[i[0] for i in c.fetchall()]

     for q,w in zip(d,e):

         l[q.encode("utf-8")]=w

     data=l

     return render_template('threat.html', data=data)
     

@app.route('/statistics')
def Statistics():

     r=[]
     d=[]
     con = sql.connect("TI.db")
     c = con.cursor()

     c.execute("SELECT count(ip) FROM IP ")
     d=[i[0] for i in c.fetchall()]

     c.execute("SELECT count(domain) FROM Domain")
     e=[i[0] for i in c.fetchall()]

     c.execute("SELECT count(url) FROM URL")
     f=[i[0] for i in c.fetchall()]

     l={'IP':d[0],'DOMAIN':e[0],'URL':f[0]}

     data=l

     return render_template('statistics.html', data=data)

@app.route('/threat_info')
def Threat_info():
     mal={}
     ser={}
     mal_host={}
     con = sql.connect("TI.db")
     c = con.cursor()  
     c.execute('SELECT threat_info FROM "ti" where threat="Malware" group by threat_info')
     d=[i[0] for i in c.fetchall()]
     c.execute('SELECT count(threat_info) FROM "ti" where threat="Malware" group by threat_info')
     e=[i[0] for i in c.fetchall()]

     for q,w in zip(d,e):

         mal[q.encode("utf-8")]=w

     c.execute('SELECT threat_info FROM "ti" where threat="Service Exploitation" group by threat_info')
     f=[i[0] for i in c.fetchall()]
     c.execute('SELECT count(threat_info) FROM "ti" where threat="Service Exploitation" group by threat_info')
     g=[i[0] for i in c.fetchall()]

     for y,z in zip(f,g):

         ser[y.encode("utf-8")]=z
     
     c.execute('SELECT threat_info FROM "ti" where threat="Malicious Host" group by threat_info')
     h=[i[0] for i in c.fetchall()]
     c.execute('SELECT count(threat_info) FROM "ti" where threat="Malicious Host" group by threat_info')
     j=[i[0] for i in c.fetchall()]
     for m,n in zip(h,j):
         mal_host[m.encode("utf-8")]=n

     data=mal
     data1=ser
     data2=mal_host



     return render_template('detail_threat_info.html', data=data,data1=data1,data2=data2)

@app.route('/')
def Index():
   return render_template("index.html")

if __name__ == '__main__':
  
   app.run(debug = True,host='0.0.0.0',port=8080)
