import os, time, random
import pandas as pd
import cx_Oracle
import re
#import tkinter  as tk


#from tkinter import filedialog
from pandas import ExcelWriter

#Funcon de Lectura  de Archivos de Ingreso    
def lectura_archivos(nombre_archivo_csv):
    
    #time.sleep(1)
    #root = tk.Tk()
    #root.withdraw()
    #path_archivo = filedialog.askopenfilename()
    nombre_archivo_txt = nombre_archivo_csv.replace(".csv",".txt")
    print(nombre_archivo_csv)
    #path_archivo = "/mnt/d/Accesos/LDAP/"+ nombre_archivo_csv
    path_archivo = "/home/seguridad/ssi/accesos/LDAP/"+ nombre_archivo_csv
    print(path_archivo)
    if ("csv" in path_archivo) or ("txt" in path_archivo) == True:
        archivo = pd.read_csv(path_archivo)
    else:
        archivo = pd.read_excel(path_archivo)
    return(archivo)

#Funcion para extraer los datos de los Correos de Ingresos   
def lectura_correos_Ingreso(nombre_archivo):
    
    #Declaracion de variables
    rol =[]
    nombre = []
    fecha_notif = []
    fecha_ingr = []
    fecha_term = []
    k=0
    
    #time.sleep(1)
    #root = tk.Tk()
    #root.withdraw()
    #path_archivo = filedialog.askdirectory()
    #path_archivo = '/mnt/d/Accesos/Ingreso_Personal/'+nombre_archivo
    path_archivo = '/home/seguridad/ssi/accesos/Ingreso_Personal/'+nombre_archivo
    arch_corr = os.listdir(path_archivo)
    path_archivo = path_archivo+"/"
    
    for k in range(0,len(arch_corr)):  
        
        archivo = open(path_archivo+arch_corr[k],'rt')
        archivo = archivo.read()
    
        #Busqueda del Rol
        rol_n = archivo.find("usuario")
        rol_f = archivo[rol_n+9:rol_n+18]
        rol_f = rol_f.replace("=0D\n","")
        rol_f = rol_f.replace("\n","")
        rol_f = rol_f[0:5]
        rol.append(rol_f)
    
        #Busqueda del Nombre
        nombre_n = archivo.find("EMPLEADO")
        if (nombre_n != -1):
            nombre_c = archivo[rol_n+19:nombre_n]
            nombre.append(nombre_c)
        else:
            nombre_n = archivo.find("NOMBRAMIENTO")
            nombre_c = archivo[rol_n+19:nombre_n]
            nombre.append(nombre_c)

        #Busqueda de Fecha de Notificacion de correo
        fecha_notif_n = archivo.find("LMTP")
        fecha_notif.append(archivo[fecha_notif_n+11:fecha_notif_n+22])
    
        #Busqueda de Fecha de Ingreso
        if int(archivo.find("DESDE")) >= 0:
            fecha_ingr_n = archivo.find("DESDE")
        else:
            fecha_ingr_n = archivo.find("DESD")     
        fecha_ingr_f = archivo[fecha_ingr_n+7:fecha_ingr_n+18]         
        fecha_ingr_f = fecha_ingr_f.replace("=\n","")
        fecha_ingr_f = fecha_ingr_f.replace("=","")
        fecha_ingr_f = fecha_ingr_f.replace(" ","")
        fecha_ingr_f = fecha_ingr_f[:9]
        fecha_ingr.append(fecha_ingr_f)

        #Busqueda Fecha Fin del Contrato
        

        if int(archivo.find("DEF"))  >= 0 or int(archivo.find("FINI"))  >= 0 :
            estado ="INDEFINIDO"
            fecha_term.append(estado)
        else:
            fecha_term_n = archivo.find("DESDE")
            fecha_term_x = archivo[fecha_term_n:fecha_term_n+31]
            fecha_term_x = fecha_term_x.replace("=\n","")
            fecha_term_x_pos = fecha_term_x.find("AL")
            fecha_term_f = fecha_term_x[fecha_term_x_pos+2:fecha_term_n+31]
            fecha_term_f = fecha_term_f.replace("=\n","")
            fecha_term_f = fecha_term_f.replace(" ","")
            fecha_term.append(fecha_term_f)
    
        #DataFrame con la informacion del correo
        ingreso_personal = pd.DataFrame({"Rol":rol,"Nombre":nombre,"Fecha_de_Notificacion":fecha_notif,"Fecha_de_Ingreso":fecha_ingr,"Fecha_de_Salida":fecha_term})
    
    return(ingreso_personal)

def path_carpeta():

    root = tk.Tk()
    root.withdraw()
    root.wm_attributes("-topmost", 1)
    path_archivo = filedialog.askdirectory(initialdir='D:Nestor/Accesos/2019/Revisión_Oct-Dic_2019/')
    root.destroy() 
    return(path_archivo)

def archivos_ingresos():

    root = tk.Tk()
    root.withdraw()
    root.wm_attributes("-topmost", 1)
    path_archivo = filedialog.askopenfile(initialdir='D:Nestor/Accesos/2019/Revisión_Oct-Dic_2019/')
    print(str(path_archivo))
    root.destroy() 
    return(path_archivo)

def crear_excel(informacion,nombre,tipo):

    print("Direccion donde desea grabar el archivo:")
    #time.sleep(1)
    #root = tk.Tk()
    #root.withdraw()
    #path_archivo = filedialog.askdirectory()
    if tipo == "ingreso":
        #path_archivo = '/mnt/d/Accesos/Reportes/'
        path_archivo = '/home/seguridad/ssi/accesos/Reportes/'
    else:
        #path_archivo = '/mnt/d/Accesos/Reportes'
        path_archivo = '/home/seguridad/ssi/accesos/Reportes'
    arch_corr = os.listdir(path_archivo)
    nombre_f = nombre + ".xlsx"
    path_f = path_archivo + nombre_f
    writer = ExcelWriter(path_f)
    informacion.to_excel(writer,nombre,index=False)
    print("\nEl archivo",nombre_f,"se ha grado exitosamente\n")
    writer.save()

def busqueda_ldap(roles,ldap):

    ldap_status = []
    ldap_rol = list(ldap['Uid'])
    ldap_status_n = list(ldap['AccountStatusLdaps']) 
    for i in range (len(roles)):
        try:
            pos = ldap_rol.index(roles[i])    
        except ValueError:
            ldap_status.append("NO EXISTE")
        else:
            ldap_status.append(ldap_status_n[pos])         
        
    return (ldap_status) 

def busqueda_correo(roles,correo):

    correo_status = []
    correo_rol = list(correo['Uid'])
    correo_status_n = list(correo['zimbraAccountStatus'])
    for i in range (len(roles)):
        try:
            pos = correo_rol.index(roles[i])
        except ValueError:
            correo_status.append("NO EXISTE")    
        else:
            correo_status.append(correo_status_n[pos])    
        
        
    return (correo_status)    

#Funcion para buscar el estado en el AD
def busqueda_ad(roles):
    
    ad=[]
    #ad_status = pd.read_excel('/mnt/d/Accesos/AD/Ad.csv')
    #ad_status = pd.read_csv('D:/Accesos/AD/Ad.xlsx')
    
    for i in range (len(roles)):
        comando_AD= "powershell -NoProfile Get-ADUser -Filter {(SamAccountName -Like \""
        comando_Fin ="\")}"
        comando = comando_AD + str(roles[i]) + comando_Fin
        comando_f = os.popen(comando).read()
        prueba = comando_f
        if int(comando_f.find("True")) >=0:
            estado = "True"
            ad.append(estado)
        else:
            estado= "False"
            ad.append(estado)
                   
    return(ad)     

def lectura_correos_Bajas(nombre_archivo, reingresos):
    
    ingresos=reingresos
       
    #Declaracion de variables
    rol =[]
    nombre = []
    fecha_notif = []
    fecha_baja = []
    fecha_term = []
    fecha_reingr = []
    fecha_notif_reingr = []
    fecha_salida = []    
    
    #print(" Ingresa el Directorio de los Archivos: ", archivo)
    #time.sleep(1)
    #root = tk.Tk()
    #root.withdraw()
    #path_archivo = filedialog.askdirectory()
    path_p = "D:/Accesos/Baja de Personal/"
    path_archivo = path_p + nombre_archivo
    arch_corr = os.listdir(path_archivo)
    path_archivo = path_archivo + "/"

    for k in range(0,len(arch_corr)):
        archivo = open(path_archivo+arch_corr[k],'rt')
        archivo = archivo.read()
     
        #Busqueda del Rol
        rol_n = archivo.find("EMPLEADO")
        rol.append(archivo[rol_n+11:rol_n+16])
    
        #Busqueda del Nombre
        #nombre_n = archivo.find("EMPLEADO")
        
        nombre_c = archivo[rol_n+18:rol_n+80]
        nombre_c = nombre_c.replace("=\n","")
        fecha_f = nombre_c.find(" SE ")
        nombre_f = nombre_c[:fecha_f-10]
        nombre.append(nombre_f)
        
        #Busqueda de Fecha de Notificacion de correo
        fecha_notif_n = archivo.find("LMTP")
        fecha_notif.append(archivo[fecha_notif_n+11:fecha_notif_n+22])
    
        #Busqueda de Fecha de Baja
        nombre_f = nombre_c[fecha_f-10:fecha_f]
        fecha_baja.append(nombre_f)
        
        #DataFrame con la informacion del correo
        baja_personal = pd.DataFrame({"Rol":rol,"Nombre":nombre,"Fecha de Salida":fecha_baja,"Fecha de Notificacion de Salida":fecha_notif})
                     
    
    #Busqueda de Reingresos
    
    for j in range (len(baja_personal['Rol'])):
        x = ingresos['Rol'].index[ingresos['Rol'] == int(baja_personal['Rol'][j])].tolist()
        if len(x) == 0:
            fecha_reingr.append(' ')
            fecha_notif_reingr.append(' ')
            fecha_salida.append(' ')
        else:
            fecha_reingr.append(ingresos['Fecha_de_Ingreso'][x[0]])
            fecha_notif_reingr.append(ingresos['Fecha_de_Notificacion'][x[0]])    
            fecha_salida.append(ingresos['Fecha_de_Salida'][x[0]])    

    baja_personal['Fecha de Reingreso'] = fecha_reingr    
    baja_personal['Fecha de Notificacion de Reingreso'] = fecha_notif_reingr    
    baja_personal['Nueva Fecha de Salida'] = fecha_salida

    return(baja_personal)

def busqueda_base_datos(usuario):

    i=0
    estado = ""
    estado1= ""
    estado2= ""
    estado3= ""
    estado_rol = []

    #Conexion a las bases de Datos
    con_dbfin = cx_Oracle.connect('54237/Nedu..1023@p4-dbfin-s:1521/DBFIN')
    con_dbsdi = cx_Oracle.connect('54237/Nedu..1023@p3-dbsdi-s:1521/dbsdi')
    con_dbarg = cx_Oracle.connect('54237/Nedu..1023@p4-dbarg:1521/dbarg11g')

    #Busqueda del Estado del Usuario
    print(len(usuario))
    for i in range(len(usuario)):
        print(i)
        
        #Peticiones
        db_command = "select * from SYS_V_ROL_USUARIO R where usuario="+"'"+ usuario[i] + "'"
        user_dbfin = pd.read_sql(db_command, con=con_dbfin)
        user_dbsdi = pd.read_sql(db_command, con=con_dbsdi)
        user_dbarg = pd.read_sql(db_command, con=con_dbarg)
        
        #Encerando variables
        estado = ""
        estado1= ""
        estado2= ""
        estado3= ""
        estado4= ""
               
        if  len(user_dbfin['USUARIO']) != 0:
            for j in range((len(user_dbfin['USUARIO']))):
                if "OPEN" in user_dbfin['ESTADO'][j] == True:
                    estado_fin = "OPEN"
                elif user_dbfin['ESTADO'][j] == "":
                    estado_fin = "False"
                else: 
                    estado_fin = (user_dbfin['ESTADO'][j])
        else: 
            estado_fin="False"
        
        if  len(user_dbsdi['USUARIO']) != 0:
            for k in range((len(user_dbsdi['USUARIO']))):
                if "OPEN" in user_dbsdi['ESTADO'][k] == True:
                    estado_sdi = "OPEN"
                elif user_dbsdi['ESTADO'][k] == "":
                    estado_sdi = "False"
                else: 
                    estado_sdi = (user_dbsdi['ESTADO'][k])
        else: 
            estado_sdi="False"

        if  len(user_dbarg['USUARIO']) != 0:
            for n in range((len(user_dbarg['USUARIO']))):
                if "OPEN" in user_dbarg['ESTADO'][n] == True:
                    estado_arg = "OPEN"
                elif user_dbarg['ESTADO'][n] == "":
                    estado_arg = "False"
                else: 
                    estado_arg = (user_dbfin['ESTADO'][n])
        else: 
            estado_arg="False"

        if (estado_fin == "OPEN"):
            estado1= "DBFIN "
        elif (estado_sdi == "OPEN") and (estado_fin != "OPEN"):
            estado2 = "SDI " 
        elif (estado_arg == "OPEN"):
            estado3 = "ARG "
        else: 
            estado4 = "False"
        
        estado = estado1 + estado2 + estado3 + estado4
        estado_rol.append(estado)
    return(estado_rol)


def ingreso_personal_main(nombre_archivo,nombre_archivo_csv):
    
    #Lectura del Archivo de Correo Y LDAP
    nombre_cl = "Correo y Ldap"
    correo = lectura_archivos(nombre_archivo_csv)
    

    #Lectura Contenido de Correos
    nombre_mail = "Correos de Ingresos"
    roles = lectura_correos_Ingreso(nombre_archivo)            
   

    #Busqueda(roles,correo)
    #Lectura del Estado del usuario en Active Directory
    ad = busqueda_ad(roles['Rol'])
    
    roles['AD'] = ad
            
    #Lectura del Estado del Correo y LDAP
    ldap_status = correo[['Uid','AccountStatusLdaps']]
    ldap = busqueda_ldap(roles['Rol'], ldap_status)
    roles['LDAP'] = ldap
    correo_status = correo[['Uid','zimbraAccountStatus']]
    correo = busqueda_correo(roles['Rol'],correo_status)
    roles['Zimbra'] = correo

    #Imprimir el Archivo
    ingreso ="ingreso"
    crear_excel(roles,nombre_archivo,ingreso)  
    x= roles.index
                         
    #roles_list = roles.values.T.tolist()
                  
    
    return(roles)     

def baja_personal_main(nombre_archivo,nombre_archivo_csv, nombre_ingreso_xlsx):
    #Datos del Status del LDPA y Correo ya se obtuvo en el ingreso se utiliza la misma variable "correo"
    nombre_cl_bajas = "Correo y Ldap"
    correo_bajas = lectura_archivos(nombre_archivo_csv)

    #Lectura Contenido de Correos
    bajas_mails = nombre_archivo
    ingresos_path = ("D:/Accesos/Reportes Ingreso de Personal/")
    ingresos = ingresos_path + nombre_ingreso_xlsx
    roles_b = pd.read_excel(ingresos)
    bajas = lectura_correos_Bajas(nombre_archivo,roles_b)
    
    #Lectura del Estado del usuario en Active Directory
    ad = busqueda_ad(bajas['Rol'])
    bajas['AD'] = ad

    #Lectura del Estado del Correo y LDAP
    ldap_status_bajas = correo_bajas[['Uid','AccountStatusLdaps']]
    ldap_bajas = busqueda_ldap(bajas['Rol'],ldap_status_bajas)
    bajas['LDAP'] = ldap_bajas
    correo_status_bajas = correo_bajas[['Uid','zimbraAccountStatus']]
    correo_bajas = busqueda_correo(bajas['Rol'],correo_status_bajas)
    bajas['Zimbra'] = correo_bajas

    #Lectura Estado en base de Datos
    estado_db = busqueda_base_datos(bajas['Rol'])
    bajas['Estado DB'] = estado_db
        
    #Imprimir el Archivo
    #print(bajas)
    baja ="baja"
    crear_excel(bajas,nombre_archivo,baja)          

    return (bajas)    
            
def baja_consulta():
    
    nombre_archivo= "Oct-Dic-2019"
    nombre_archivo_csv = "Oct-Dic-2019.csv"
    nombre_ingreso_xlsx = "Oct-Dic-2019.xlsx"
    
    #Datos del Status del LDPA y Correo ya se obtuvo en el ingreso se utiliza la misma variable "correo"
    nombre_cl_bajas = "Correo y Ldap"
    correo_bajas = lectura_archivos(nombre_archivo_csv)

    #Lectura Contenido de Correos
    bajas_mails = nombre_archivo
    ingresos_path = ("D:/Accesos/Reportes Ingreso de Personal/")
    ingresos = ingresos_path + nombre_ingreso_xlsx
    roles_b = pd.read_excel(ingresos)
    bajas = lectura_correos_Bajas(nombre_archivo,roles_b)
    
    #Lectura del Estado del usuario en Active Directory
    ad = busqueda_ad(bajas['Rol'])
    bajas['AD'] = ad

    #Lectura del Estado del Correo y LDAP
    ldap_status_bajas = correo_bajas[['Uid','AccountStatusLdaps']]
    ldap_bajas = busqueda_ldap(bajas['Rol'],ldap_status_bajas)
    bajas['LDAP'] = ldap_bajas
    correo_status_bajas = correo_bajas[['Uid','zimbraAccountStatus']]
    correo_bajas = busqueda_correo(bajas['Rol'],correo_status_bajas)
    bajas['Zimbra'] = correo_bajas

    #Lectura Estado en base de Datos
    estado_db = busqueda_base_datos(bajas['Rol'])
    bajas['Estado DB'] = estado_db
        
    #Imprimir el Archivo
    #print(bajas)
    #crear_excel(bajas,nombre_archivo)    

    return (bajas) 
                     
def estado_mensual_ingresos(mes,year, dia):

    tarea_sgi = []

    #Conexión Base de Datos
    con_dbsgi = cx_Oracle.connect('aduque/Quito2020+-@p1-dbeeq:1521/dbeeq')
    con_dbfin = cx_Oracle.connect('54237/Nedu..1023@p4-dbfin-s:1521/DBFIN')

    #Transformación del mes
    if len(mes)==1:
        mes_p = int(mes) - 1
        mes_p = "0"+ str(mes_p)
        mes = "0"+ mes

    if len(dia)==1:
        dia = "0" + dia

    #Busqueda de los ingresos en el ultimo mes  
    db_command = "Select * from FCB_V_DATO_EMPL where to_char(FEC_INGRESO,'yyyymmdd')>"+year+mes_p+str(dia)
    
    print (dia)
    print (mes_p)
    print (type(mes))
    ingresos = pd.read_sql(db_command, con=con_dbfin)

    #Busque de tarea del SGI por cada ingreso
    for i in range(len(ingresos['ROL_EMPL'])):
        db_command = "select * from sgi_tareas where asunto like 'INFORME DE INGRESO%PERSONAL%"+ingresos['ROL_EMPL'][i]+"%'"
        tarea = pd.read_sql(db_command, con=con_dbsgi)
        if len(tarea) > 0:
            tarea_sgi.append(tarea['COD_TAREA'][0])
        else:
            db_command = "select * from sgi_tareas where asunto like 'INFORME%"+ingresos['ROL_EMPL'][i]+"%'"
            tarea = pd.read_sql(db_command, con=con_dbsgi)
            if len(tarea) > 0:
                tarea_sgi.append(tarea['COD_TAREA'][0])
            else:
                tarea_sgi.append("No existe")
    
    #Lectura del Estado del usuario en Active Directory
    ad = busqueda_ad(ingresos['ROL_EMPL'])
    
    #Lectura Estado en base de Datos
    estado_db = busqueda_base_datos(ingresos['ROL_EMPL'])
    estado_mensual = pd.DataFrame({"Rol":ingresos['ROL_EMPL'],"Nombre":ingresos['NOMB_EMPL'],"Fecha Ingreso":ingresos['FEC_INGRESO'],"Tarea_SGI":tarea_sgi,"Estado DB":estado_db, "Estado AD":ad})
    estado_mensual.sort_values(by=['Fecha Ingreso'], inplace=True)

    #Resumen 
    return (estado_mensual)        


def estado_mensual_bajas(mes,year, dia):
    
    bajas_eeq_nombre = []

    #Conexión Base de Datos
    con_dbfin = cx_Oracle.connect('54237/Nedu..1023@p4-dbfin-s:1521/DBFIN')

    #Transformación del mes
    if len(mes)==1:
        mes_p = int(mes) - 1
        mes_p = "0"+ str(mes_p)
        mes = "0"+ mes

    if len(dia)==1:
        dia = "0" + dia
    
    #Busqueda de los ingresos en el ultimo mes  
    db_command_sp = "Select * from FCB_V_DATO_EMPL where to_char(FEC_SALIDA,'yyyymmdd') BETWEEN (" +year+mes_p+dia+")and("+ year+mes+dia+")"
    db_command_eeq = "Select * from APA_EMPLEADO where to_char(FEC_SALIDA,'yyyymmdd') BETWEEN (" +year+mes_p+dia+")and("+ year+mes+dia+")"

    bajas_sp = pd.read_sql(db_command_sp, con=con_dbfin)
    bajas_eeq = pd.read_sql(db_command_eeq, con=con_dbfin)
    
    #Nombre del empleado
    for i in range(len(bajas_eeq['ROL'])):
                       
        if bajas_eeq['P_APELLIDO'][i]== "":
            bajas_eeq_nombre.append(str(bajas_eeq['NOMBRES'][i])+" "+str(bajas_eeq['S_APELLIDO'][i]))
        elif bajas_eeq['S_APELLIDO'][i] == "":
            bajas_eeq_nombre.append(str(bajas_eeq['NOMBRES'][i])+" " +str(bajas_eeq['P_APELLIDO'][i]))
        else:
            bajas_eeq_nombre.append(str(bajas_eeq['NOMBRES'][i])+" "+ str(bajas_eeq['P_APELLIDO'][i])+" "+str(bajas_eeq['S_APELLIDO'][i]))
    
    bajas_sp = pd.DataFrame({'Rol':bajas_sp['ROL_EMPL'],'Nombre':bajas_sp['NOMB_EMPL'],'Fecha de Salida':bajas_sp['FEC_SALIDA']})
    bajas_eeq = pd.DataFrame({'Rol':bajas_eeq['ROL'],'Fecha de Salida':bajas_eeq['FEC_SALIDA']})
    
    bajas_eeq = pd.DataFrame({'Rol':bajas_eeq['Rol'],'Nombre':bajas_eeq_nombre,'Fecha de Salida':bajas_eeq['Fecha de Salida']})
    bajas = pd.concat([bajas_sp,bajas_eeq], ignore_index=True, sort=False)
    print (bajas)

    #Lectura del Estado del usuario en Active Directory
    ad = busqueda_ad(bajas['Rol'])
    bajas['Estado AD'] = ad
    
    #Lectura Estado en base de Datos
    estado_db = busqueda_base_datos(bajas['Rol'])
    bajas['Estado DB'] = estado_db

    bajas.sort_values(by=['Fecha de Salida'], inplace=True)
    return(bajas)


def suspension():

   #Revision de Suspension

    rol =[]
    nombre = []
    fecha_inicio = []
    fecha_fin = []
    fecha_notif= []
    observacion= []
    habilitacion= []
    deshabilitacion= []
    k=0
        
    # Lectura de los Correos de Suspension de Accesos

    path_archivo = 'D:/Accesos/Suspension/Ene-Mar-2020'#+nombre_archivo
    arch_corr = os.listdir(path_archivo)
    path_archivo = path_archivo+"/"

    #Lectura de Registro CDN

    registro = pd.read_excel("D:/Accesos/Registros CDN/Ene-Mar-2020.xlsx")

        
    for k in range(0,len(arch_corr)):  
            
        archivo = open(path_archivo+arch_corr[k],'rt')
        archivo = archivo.read()
        
        #Busqueda del Rol
        rol_n = archivo.find("usuario")
        rol_f = archivo[rol_n+8:rol_n+13]
        rol.append(rol_f)
        
    
        #Busqueda del Nombre
        nombre_c = archivo[rol_n+14:rol_n+60]
        nombre_f = nombre_c.find("=0D")
        nombre_c = nombre_c[:nombre_f]
        nombre.append(nombre_c)
        
        #Busqueda de Fecha Inicio
        fecha_n = archivo.find("desde")
        fecha_f = archivo[fecha_n+6:fecha_n+15]
        fecha_inicio.append(fecha_f)
        
        #Busqueda de Fecha Fin 
        fecha_fn = archivo.find("hasta")
        fecha_ff = archivo[fecha_fn+6:fecha_fn+15]
        fecha_fin.append(fecha_ff)
        
        #Busqueda de Notificacion de Correo
        fecha_notif_n = archivo.find("Date")
        fecha_notif_c = archivo[fecha_notif_n+6:fecha_notif_n+40]
        fecha_notif_ini = fecha_notif_c.find(",")
        fecha_notif_fin= fecha_notif_c.find(":")
        fecha_notif_f = fecha_notif_c[fecha_notif_ini+2:fecha_notif_fin-2]
        fecha_notif.append(fecha_notif_f)
        

    #DataFrame con la informacion del correo
    suspension_personal = pd.DataFrame({"Rol":rol,"Nombre":nombre,"Fecha Inicio":fecha_inicio,"Fecha Fin":fecha_fin,"Fecha Notificacion":fecha_notif})

    #Transformacion de las fechas a tipo fecha
    suspension_personal['Fecha Inicio'] = pd.to_datetime(suspension_personal['Fecha Inicio'])
    suspension_personal['Fecha Fin'] = pd.to_datetime(suspension_personal['Fecha Fin'])
    suspension_personal['Fecha Notificacion'] = pd.to_datetime(suspension_personal['Fecha Notificacion'])

    for i in range(0,len(arch_corr)):
        x = registro['USUARIO'].index[registro['USUARIO'] == int(suspension_personal['Rol'][i])].tolist()
        if (len(x) == 2):
            n = registro['FECHA'][x[0]]
            
            m = registro['FECHA'][x[1]]
            
            if (n > m):
                habilitacion.append(n.date())
                deshabilitacion.append(m.date()) 
            else:
                habilitacion.append(m.date())
                deshabilitacion.append(n.date())
        else:
            habilitacion.append("Revisar")
            deshabilitacion.append("Revisar")
        
        if (suspension_personal['Fecha Inicio'][i] < suspension_personal['Fecha Notificacion'][i]):
            observacion.append("Notificacion Tardía")
        else:
            observacion.append("A tiempo ")


    suspension_personal["Deshabilitacion"] = deshabilitacion
    suspension_personal["Habilitacion"] = habilitacion
    suspension_personal["Observacion"] = observacion