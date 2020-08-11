from flask import Flask, render_template, request
from flask import make_response, Response
from flask import session
from flask import flash
from flask import g
from flask_wtf.csrf import CSRFProtect
from flask import url_for
from flask import redirect
from datetime import datetime

from config import DevelopmentConfig
from models import db, User
from ingreso_bajas import *
import forms

import json
import pandas as pd
#import tkinter  as tk
#from tkinter import filedialog
import os



app = Flask(__name__)
app.config.from_object(DevelopmentConfig)
csrf = CSRFProtect()


@app.errorhandler(404)
def page_nof_found(e):
    return render_template('notfound.html')

@app.before_request
def before_request():
    if 'username' not in session and request.endpoint in ['acceso','index','Ingreso','baja_de_personal']:
        return redirect (url_for('login'))
    elif 'username' in session and request.endpoint in ['login',]:
        
        return redirect(url_for('index'))

@app.after_request
def after_request(response):
    return response
   

@app.route('/')
def index():
    if 'username' in session:
        username = session['username']
        print (username)
    custome_cookie = request.cookies.get('custome_cookie','Undefined')
    return render_template('index.html',usuario=username)


@app.route('/logout')
def logout():
    if 'username' in session:
        session.pop('username')
    return redirect(url_for('login'))

@app.route('/login', methods = ['GET', 'POST'])
def login():
    login_form = forms.LoginForm(request.form)
    if request.method == 'POST' and login_form.validate():
        username = login_form.username.data
        password = login_form.password.data
        user = User.query.filter_by(username = username).first()
        if user is not None and user.verify_password(password):
            session['username'] = username
            time.sleep(1)
            return redirect(url_for('index'))
        else:
            error_message = 'Usuario o contraseña no validos'
            flash(u'Usuario o contraseña no validos','error')
    
    return render_template('login.html', form = login_form)

@app.route('/create', methods =['GET','POST'])
def create():
    create_form = forms.CreateForm(request.form)
    if request.method == 'POST' and create_form.validate():
        user = User(create_form.username.data,
                    create_form.password.data,
                    create_form.perfil.data)
        username = create_form.username.data
        user_check = User.query.filter_by(username = username).first()
        if user_check is not None:
            error_message = 'El nombre de usuario ya existe por favor escriba uno diferente'
            flash(u'El nombre de usuario ya existe por favor escriba uno diferente','error')
        else:
            db.session.add(user)
            db.session.commit()
            success_message = 'Usuario registrado'
            flash(u'Usuario registrado','success')

    return render_template('create.html', form = create_form)

@app.route('/cookie')
def cookie():
    response = make_response (render_template('cookie.html'))
    response.set_cookie('custome_cookie','Acessos')
    return response

@app.route('/acceso')
def acceso():
   return render_template('acceso.html')




@app.route('/Ingreso', methods =['GET','POST'])
def Ingreso():
    
       
    #Variables para presentar el ultimo reporte y el estado del ultimo mes
    meses = {'1':'ENERO','2':'FEBRERO','3':'MARZO','4':'ABRIL','5':'MAYO','6':'JUNIO','7':'JULIO','8':'AGOSTO','9':'SEPTIEMBRE','10':'OCTUBRE','11':'NOVIEMBRE','12':'DICIEMBRE'}
    ultimo_reporte = {'4':'Ene-Mar','5':'Ene-Mar','6':'Ene-Mar','7':'Abr-Jun','8':'Abr-Jun','9':'Abr-Jun','10':'Jul-Sep','11':'Jul-Sep','12':'Jul-Sep','1':'Oct-Dic','2':'Oct-Dic','3':'Oct-Dic'}
    

    # Se obtiene el tiempo
    tiempo=datetime.now()
    mes = str(tiempo.month)
    year_t = str(tiempo.year)
    dia = str(tiempo.day)
    if len(mes)==1:
       dia_p = "0"+ str(dia)
    periodo_consulta = dia_p+ "-" +  meses[str(int(mes)-1)]   + " AL "+ dia_p +"-" + meses[mes] + " " + year_t  
    periodo = meses[mes] + " " + str(year_t)
    
       
    # Se muestra el último reporte trimestral generado
    ingresos_path = ("D:/Accesos/Reportes Ingreso de Personal/")
    year_t_a = str(tiempo.year - 1)
    mes_t = ultimo_reporte[mes]
    nombre_archivo_xlsx = mes_t +"-"+ year_t_a +".xlsx"
    nombre_archivo = mes_t +"-"+ year_t_a
    ingresos = ingresos_path + nombre_archivo_xlsx
    roles = pd.read_excel(ingresos)

    #Revisión de existencia de archivos
    req_ldap_ad= os.listdir(r'D:\Accesos\Archivo_LDAP_Correo')
    req_correos = os.listdir(r'D:\Accesos\Ingreso de Personal')
    req_registro =  os.listdir(r"D:\Accesos\Reportes Ingreso de Personal")

    #Variable de grafico requisitos logos
    grafico = {'visto':'visto.PNG','x':'x.PNG'}
    g.figura= grafico

    #Validación de Perfiles
    usuario = session['username']
    user_check = User.query.filter_by(username = usuario).first()
    perfil = user_check.perfil

    #Validacon botones de accion
    ingresos_form = forms.IngresosForm(request.form)
    if request.method=='POST':
        if request.form['Modificar'] == 'Modificar1':
            path = path_carpeta() 
            return render_template('ingresos.html',form = ingresos_form, path=path)
        elif request.form['Modificar'] == 'Modificar.':
            path1 = archivos_ingresos()
            return render_template('ingresos.html',form = ingresos_form, path1=path1)
        elif request.form['Modificar'] == 'Ver Registro':
            mes = ingresos_form.mes.data
            year = ingresos_form.year.data
            nombre_archivo = mes +"-"+ year
            nombre_archivo_csv = mes +"-"+ year +".csv"
            nombre_archivo_xlsx = mes +"-"+ year +".xlsx"
            print (nombre_archivo,nombre_archivo_csv,nombre_archivo_xlsx)
            if ((nombre_archivo_xlsx in req_registro) == True):
                ingresos_path = ("D:/Accesos/Reportes Ingreso de Personal/")
                ingresos = ingresos_path + nombre_archivo_xlsx
                roles = pd.read_excel(ingresos)
                return render_template('ingresos.html',form = ingresos_form, mes_actual = periodo_consulta, perfil=perfil, fecha=nombre_archivo,ldap="Archivo_LDAP_Correo/"+nombre_archivo_csv,  tables=[roles.to_html(classes='data')],
                                                        titles=roles.columns.values, logoingr=g.figura['visto'], logoingr1=g.figura['visto'], logoingr2=g.figura['visto'])
            else:
                flash('No existe registro para {}'.format(nombre_archivo))
                return render_template('ingresos.html',form = ingresos_form, mes_actual = periodo_consulta, perfil=perfil, fecha=nombre_archivo,ldap="Archivo_LDAP_Correo/"+nombre_archivo_csv,  logoingr=g.figura['x'], 
                logoingr1=g.figura['x'], logoingr2=g.figura['x'])

        elif request.form['Modificar'] == 'Generar':
            mes = ingresos_form.mes.data
            year = ingresos_form.year.data
            nombre_archivo = mes +"-"+ year
            nombre_archivo_csv = mes +"-"+ year +".csv"
            print (nombre_archivo,nombre_archivo_csv)
            if ((nombre_archivo in req_correos) == True) and ((nombre_archivo_csv in req_ldap_ad) == True):
                ingresos_nuevo = ingreso_personal_main(nombre_archivo,nombre_archivo_csv)
                return render_template('ingresos.html',form = ingresos_form, fecha=nombre_archivo, perfil=perfil, ldap=nombre_archivo_csv,  tables=[ingresos_nuevo.to_html(classes='data')],
                                                        titles=ingresos_nuevo.columns.values, logoingr=g.figura['visto'], logoingr1=g.figura['visto'], logoingr2=g.figura['visto'])
            elif ((nombre_archivo in req_correos) == True):
                return render_template('ingresos.html',form = ingresos_form, mes_actual = periodo_consulta, fecha=nombre_archivo, perfil=perfil, logoingr=g.figura['x'], logoingr1=g.figura['visto'], logoingr2=g.figura['x'])
            elif ((nombre_archivo_csv in req_ldap_ad) == True):
                return render_template('ingresos.html',form = ingresos_form, mes_actual = periodo_consulta, fecha=nombre_archivo, perfil=perfil, logoingr=g.figura['x'], logoingr1=g.figura['x'], logoingr2=g.figura['visto'])
            else:
                flash('No existe ese periodo')
                return render_template('ingresos.html',form = ingresos_form, mes_actual = periodo_consulta, fecha=nombre_archivo, perfil=perfil, logoingr=g.figura['x'], logoingr1=g.figura['x'], logoingr2=g.figura['x'])
        elif request.form['Modificar'] == 'Consultar':
            # Se obtiene estado de ingresos del ultimo mes
            estado_mensual = estado_mensual_ingresos(mes,year_t, dia)
            return render_template('ingresos.html',form = ingresos_form, mes_actual = periodo_consulta , perfil=perfil, fecha=nombre_archivo, tables=[roles.to_html(classes='data')],
                                                        titles=roles.columns.values, tables_mensual=[estado_mensual.to_html(classes='data')],
                                                        titles_mensual=estado_mensual.columns.values, logoingr=g.figura['x'], logoingr1=g.figura['x'], logoingr2=g.figura['x'],
                                                        quitar_texto="display:none")

        
    return render_template('ingresos.html',form = ingresos_form,perfil=perfil, mes_actual = periodo_consulta , fecha=nombre_archivo, ldap=nombre_archivo+".csv" , tables=[roles.to_html(classes='data')],
                                                        titles=roles.columns.values, logoingr=g.figura['visto'], logoingr1=g.figura['visto'], logoingr2=g.figura['visto'])



@app.route('/Baja', methods =['GET','POST'])
def baja_de_personal():

     #Variables para presentar el ultimo reporte y el estado del ultimo mes
    meses = {'1':'ENERO','2':'FEBRERO','3':'MARZO','4':'ABRIL','5':'MAYO','6':'JUNIO','7':'JULIO','8':'AGOSTO','9':'SEPTIEMBRE','10':'OCTUBRE','11':'NOVIEMBRE','12':'DICIEMBRE'}
    ultimo_reporte = {'4':'Ene-Mar','5':'Ene-Mar','6':'Ene-Mar','7':'Abr-Jun','8':'Abr-Jun','9':'Abr-Jun','10':'Jul-Sep','11':'Jul-Sep','12':'Jul-Sep','1':'Oct-Dic','2':'Oct-Dic','3':'Oct-Dic'}

    #Validación de Perfiles
    usuario = session['username']
    user_check = User.query.filter_by(username = usuario).first()
    perfil = user_check.perfil

    #Revisión de existencia de archivos
    req_ldap_ad= os.listdir(r'D:\Accesos\Archivo_LDAP_Correo')
    req_correos = os.listdir(r'D:\Accesos\Baja de Personal')
    req_ingreso = os.listdir(r'D:\Accesos\Reportes Ingreso de Personal')
    req_registro = os.listdir(r"D:\Accesos\Reportes Baja de Personal")
    
    # Se obtiene el tiempo
    tiempo=datetime.now()
    mes = str(tiempo.month)
    year_t = str(tiempo.year)
    dia = str(tiempo.day)
    if len(mes)==1:
       dia_p = "0"+ str(dia)
    periodo_consulta = dia_p+ "-" +  meses[str(int(mes)-1)]   + " AL "+ dia_p +"-" + meses[mes] + " " + year_t  
    periodo = meses[mes] + " " + str(year_t)

    # Se muestra el último reporte trimestral generado
    bajas_path = ("D:/Accesos/Reportes Baja de Personal/")
    year_t_a = str(tiempo.year - 1)
    mes_t = ultimo_reporte[mes]
    nombre_archivo_xlsx = mes_t +"-"+ year_t_a +".xlsx"
    nombre_archivo = mes_t +"-"+ year_t_a
    bajas = bajas_path + nombre_archivo_xlsx
    roles = pd.read_excel(bajas)

    
    grafico = {'visto':'visto.PNG','x':'x.PNG'}
    g.figura= grafico
    bajas_form=forms.BajasForm(request.form)
    if request.method=='POST':
        if request.form['Modificar'] == 'Modificar1':
            path = path_carpeta() 
            return render_template('bajas.html',form = bajas_form, path=path)
        elif request.form['Modificar'] == 'Modificar2':
            path1 = archivos_ingresos()
            return render_template('bajas.html',form = bajas_form, path1=path1)
        elif request.form['Modificar'] == 'Ver Registro':
            mes = bajas_form.mes.data
            year = bajas_form.year.data
            nombre_archivo = mes +"-"+ year
            nombre_archivo_csv = mes +"-"+ year +".csv"
            nombre_archivo_xlsx = mes +"-"+ year +".xlsx"
            print (nombre_archivo,nombre_archivo_csv,nombre_archivo_xlsx)
            if ((nombre_archivo_xlsx in req_registro) == True):
                bajas_path = ("D:/Accesos/Reportes Baja de Personal/")
                bajas = bajas_path + nombre_archivo_xlsx
                roles = pd.read_excel(bajas)
                return render_template('bajas.html',form = bajas_form, mes_actual = periodo_consulta, perfil=perfil, fecha=nombre_archivo,ldap=nombre_archivo+".csv",  tables=[roles.to_html(classes='data')],
                                                        titles=roles.columns.values, logoingr=g.figura['visto'], logoingr1=g.figura['visto'], logoingr2=g.figura['visto'])
            else:
                flash('No existe registro para {}'.format(nombre_archivo))
                return render_template('bajas.html',form = bajas_form, mes_actual = periodo_consulta, perfil=perfil, fecha=nombre_archivo,ldap=nombre_archivo+".csv",  logoingr=g.figura['x'], 
                logoingr1=g.figura['x'], logoingr2=g.figura['x'])
        
        elif request.form['Modificar'] == 'Generar':
            mes = bajas_form.mes.data
            year = bajas_form.year.data
            nombre_archivo = mes +"-"+ year
            nombre_archivo_csv = mes +"-"+ year +".csv"
            nombre_ingreso_xlsx = mes +"-"+ year +".xlsx"
            print (nombre_archivo,nombre_archivo_csv,nombre_ingreso_xlsx)
            if ((nombre_archivo in req_correos) == True) and ((nombre_archivo_csv in req_ldap_ad) == True) and ((nombre_ingreso_xlsx in req_ingreso) == True):
                roles = baja_personal_main(nombre_archivo, nombre_archivo_csv, nombre_ingreso_xlsx)
                flash(u'El archivo se ha {}'.format(nombre_ingreso_xlsx) +' se ha generado','success')
                return render_template('bajas.html', perfil=perfil, form = bajas_form, fecha=nombre_archivo, ldap=nombre_ingreso_xlsx,  tables=[roles.to_html(classes='data')],
                                                        titles=roles.columns.values, logoingr=g.figura['visto'], logoingr1=g.figura['visto'], logoingr2=g.figura['visto'],cargando="")
            elif ((nombre_archivo in req_correos) == True):
                return render_template('bajas.html', perfil=perfil, form = bajas_form, fecha=nombre_archivo, logoingr=g.figura['x'], logoingr1=g.figura['visto'], logoingr2=g.figura['x'])
            elif ((nombre_ingreso_xlsx in req_ldap_ad) == True):
                return render_template('bajas.html', perfil=perfil, form = bajas_form, fecha=nombre_archivo, logoingr=g.figura['x'], logoingr1=g.figura['x'], logoingr2=g.figura['visto'])
            else:
                flash('No existe ese periodo')
                return render_template('bajas.html', perfil=perfil, form = bajas_form, fecha=nombre_archivo, logoingr=g.figura['x'], logoingr1=g.figura['x'], logoingr2=g.figura['x'])
        elif request.form['Modificar'] == 'Consultar':
            # Se obtiene estado de bajas del ultimo mes
            estado_mensual = estado_mensual_bajas(mes,year_t, dia)
            return render_template('bajas.html',form = bajas_form, mes_actual = periodo_consulta , perfil=perfil, fecha=nombre_archivo, tables=[roles.to_html(classes='data')],
                                                        titles=roles.columns.values, tables_mensual=[estado_mensual.to_html(classes='data')],
                                                        titles_mensual=estado_mensual.columns.values, logoingr=g.figura['x'], logoingr1=g.figura['x'], logoingr2=g.figura['x'],
                                                        quitar_texto="display:none")
    
    return render_template('bajas.html',form = bajas_form,perfil=perfil, mes_actual = periodo_consulta , fecha=nombre_archivo, ldap=nombre_archivo_xlsx , tables=[roles.to_html(classes='data')],
                                                        titles=roles.columns.values, logoingr=g.figura['visto'], logoingr1=g.figura['visto'], logoingr2=g.figura['visto'])


@app.route('/suspension')
def suspension():
    #Variables para presentar el ultimo reporte y el estado del ultimo mes
    meses = {'1':'ENERO','2':'FEBRERO','3':'MARZO','4':'ABRIL','5':'MAYO','6':'JUNIO','7':'JULIO','8':'AGOSTO','9':'SEPTIEMBRE','10':'OCTUBRE','11':'NOVIEMBRE','12':'DICIEMBRE'}
    ultimo_reporte = {'4':'Ene-Mar','5':'Ene-Mar','6':'Ene-Mar','7':'Abr-Jun','8':'Abr-Jun','9':'Abr-Jun','10':'Jul-Sep','11':'Jul-Sep','12':'Jul-Sep','1':'Oct-Dic','2':'Oct-Dic','3':'Oct-Dic'}
    

    # Se obtiene el tiempo
    tiempo=datetime.now()
    mes = str(tiempo.month)
    year_t = str(tiempo.year)
    dia = str(tiempo.day)
    if len(mes)==1:
       dia_p = "0"+ str(dia)
    periodo_consulta = dia_p+ "-" +  meses[str(int(mes)-1)]   + " AL "+ dia_p +"-" + meses[mes] + " " + year_t  
    periodo = meses[mes] + " " + str(year_t)
    
       
    # Se muestra el último reporte trimestral generado
    ingresos_path = ("D:/Accesos/Reportes Ingreso de Personal/")
    year_t_a = str(tiempo.year - 1)
    mes_t = ultimo_reporte[mes]
    nombre_archivo_xlsx = mes_t +"-"+ year_t_a +".xlsx"
    nombre_archivo = mes_t +"-"+ year_t_a
    ingresos = ingresos_path + nombre_archivo_xlsx
    roles = pd.read_excel(ingresos)

    #Revisión de existencia de archivos
    req_ldap_ad= os.listdir(r'D:\Accesos\Archivo_LDAP_Correo')
    req_correos = os.listdir(r'D:\Accesos\Ingreso de Personal')
    req_registro =  os.listdir(r"D:\Accesos\Reportes Ingreso de Personal")

    #Variable de grafico requisitos logos
    grafico = {'visto':'visto.PNG','x':'x.PNG'}
    g.figura= grafico

    #Validación de Perfiles
    usuario = session['username']
    user_check = User.query.filter_by(username = usuario).first()
    perfil = user_check.perfil

    #Validacon botones de accion
    ingresos_form = forms.IngresosForm(request.form)
    if request.method=='POST':
        if request.form['Modificar'] == 'Modificar1':
            path = path_carpeta() 
            return render_template('suspension.html',form = ingresos_form, path=path)
        elif request.form['Modificar'] == 'Modificar.':
            path1 = archivos_ingresos()
            return render_template('suspension.html',form = ingresos_form, path1=path1)
        elif request.form['Modificar'] == 'Ver Registro':
            mes = ingresos_form.mes.data
            year = ingresos_form.year.data
            nombre_archivo = mes +"-"+ year
            nombre_archivo_csv = mes +"-"+ year +".csv"
            nombre_archivo_xlsx = mes +"-"+ year +".xlsx"
            print (nombre_archivo,nombre_archivo_csv,nombre_archivo_xlsx)
            if ((nombre_archivo_xlsx in req_registro) == True):
                ingresos_path = ("D:/Accesos/Reportes Ingreso de Personal/")
                ingresos = ingresos_path + nombre_archivo_xlsx
                roles = pd.read_excel(ingresos)
                return render_template('suspension.html',form = ingresos_form, mes_actual = periodo_consulta, perfil=perfil, fecha=nombre_archivo,ldap="Archivo_LDAP_Correo/"+nombre_archivo_csv,  tables=[roles.to_html(classes='data')],
                                                        titles=roles.columns.values, logoingr=g.figura['visto'], logoingr1=g.figura['visto'], logoingr2=g.figura['visto'])
            else:
                flash('No existe registro para {}'.format(nombre_archivo))
                return render_template('suspension.html',form = ingresos_form, mes_actual = periodo_consulta, perfil=perfil, fecha=nombre_archivo,ldap="Archivo_LDAP_Correo/"+nombre_archivo_csv,  logoingr=g.figura['x'], 
                logoingr1=g.figura['x'], logoingr2=g.figura['x'])

        elif request.form['Modificar'] == 'Generar':
            mes = ingresos_form.mes.data
            year = ingresos_form.year.data
            nombre_archivo = mes +"-"+ year
            nombre_archivo_csv = mes +"-"+ year +".csv"
            print (nombre_archivo,nombre_archivo_csv)
            if ((nombre_archivo in req_correos) == True) and ((nombre_archivo_csv in req_ldap_ad) == True):
                ingresos_nuevo = ingreso_personal_main(nombre_archivo,nombre_archivo_csv)
                return render_template('suspension.html',form = ingresos_form, fecha=nombre_archivo, perfil=perfil, ldap=nombre_archivo_csv,  tables=[ingresos_nuevo.to_html(classes='data')],
                                                        titles=ingresos_nuevo.columns.values, logoingr=g.figura['visto'], logoingr1=g.figura['visto'], logoingr2=g.figura['visto'])
            elif ((nombre_archivo in req_correos) == True):
                return render_template('suspension.html',form = ingresos_form, mes_actual = periodo_consulta, fecha=nombre_archivo, perfil=perfil, logoingr=g.figura['x'], logoingr1=g.figura['visto'], logoingr2=g.figura['x'])
            elif ((nombre_archivo_csv in req_ldap_ad) == True):
                return render_template('suspension.html',form = ingresos_form, mes_actual = periodo_consulta, fecha=nombre_archivo, perfil=perfil, logoingr=g.figura['x'], logoingr1=g.figura['x'], logoingr2=g.figura['visto'])
            else:
                flash('No existe ese periodo')
                return render_template('suspension.html',form = ingresos_form, mes_actual = periodo_consulta, fecha=nombre_archivo, perfil=perfil, logoingr=g.figura['x'], logoingr1=g.figura['x'], logoingr2=g.figura['x'])
        elif request.form['Modificar'] == 'Consultar':
            # Se obtiene estado de ingresos del ultimo mes
            estado_mensual = estado_mensual_ingresos(mes,year_t, dia)
            return render_template('suspension.html',form = ingresos_form, mes_actual = periodo_consulta , perfil=perfil, fecha=nombre_archivo, tables=[roles.to_html(classes='data')],
                                                        titles=roles.columns.values, tables_mensual=[estado_mensual.to_html(classes='data')],
                                                        titles_mensual=estado_mensual.columns.values, logoingr=g.figura['x'], logoingr1=g.figura['x'], logoingr2=g.figura['x'],
                                                        quitar_texto="display:none")

        
    return render_template('suspension.html',form = ingresos_form,perfil=perfil, mes_actual = periodo_consulta , fecha=nombre_archivo, ldap=nombre_archivo+".csv" , tables=[roles.to_html(classes='data')],
                                                        titles=roles.columns.values, logoingr=g.figura['visto'], logoingr1=g.figura['visto'], logoingr2=g.figura['visto'])



@app.route('/progress')
def progress():
	def baja():
		ad=[]
		for i in range (11):
			comando_AD= "powershell -NoProfile Get-ADUser -Filter {(SamAccountName -Like \""
			rol = ["54237","32440","37032","56160","47777","54237","32440","37032","56160","47777","56160"]
			comando_Fin ="\")}"
			comando = comando_AD + str(rol[i]) + comando_Fin
			comando_f = os.popen(comando).read()
			prueba = comando_f
			if int(comando_f.find("True")) >=0:
				estado = "True"
				ad.append(estado)
			else:
				estado= "False"
				ad.append(estado)
			yield "data:" + str(i*10) + "\n\n" 
			print(ad[i])
        
        
		#Lectura del Estado del usuario en Active Directory
	   	
		
	return Response(baja(), mimetype= 'text/event-stream')


@app.route('/ajax-login', methods = ['POST'])
def ajax_login():
    print (request.form)
    username = request.form['username']
    response = {'status':200,"Usuario":username,'id':1}
    return json.dumps(response)
    
if __name__ == '__main__':
    csrf.init_app(app)
    db.init_app(app)
    with app.app_context():
        db.create_all()
    app.run(host='192.168.36.132',port=8000)


