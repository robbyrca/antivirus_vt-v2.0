#Importamos las librerias necesarias para el proyecto
import shutil,os,json, time, datetime, requests, pyudev
import mysql.connector
from urllib import response
from pathlib import Path

#Determinamos las rutas
file_here = '/home/antivirus_vt-v2.0/archivo'
file_temp = '/home/antivirus_vt-v2.0/archivos/temp'
file_quarantine = '/home/antivirus_vt-v2.0/archivos/cuarentena'
file_revised = '/home/antivirus_vt-v2.0/archivos/revisado'
file_result0 = '/var/www/html/antivirus/archivos'
file_result1 = '/var/www/html/antivirus/cuarentena'
file_usb = '/media/usb'
file_log = "/var/www/html/antivirus/logs/antivirus.log"

#Definimos las variables para conectar con la base de datos
mydb = mysql.connector.connect(
  host="localhost",
  user="robbyrca",
  password="QWEqwe123!",
  database="antivirus",
  auth_plugin='mysql_native_password'
)

#Definimos la función copiar
def copiar(carpeta_origen, carpeta_desti):
    # Comprovar si la carpeta de desti existeix, si no, crear-la
    if not os.path.exists(carpeta_desti):
        os.makedirs(carpeta_desti)

    # Per a cada carpeta, subcarpeta i fitxer que es trobi a la carpeta origen
    for carpeta, subcarpetes, fitxers in os.walk(carpeta_origen):
        for fitxer in fitxers:
            # Obtenir la ruta completa del fitxer
            ruta_completa = os.path.join(carpeta, fitxer)
            print (ruta_completa)
            # Copiar el fitxer a la carpeta de desti
            shutil.copy(ruta_completa, carpeta_desti)

#Definimos la función que va revisar la existencia de archivos en la ruta
def checkFileExistance(enviocheck):
    try:
        with open(enviocheck, 'r') as f:
            return True
    except FileNotFoundError as e:
        return False
    except IOError as e:
        return False

#Definimos la función que va a enviar y recoger el id del archivo
def obtener_id(file):
    global timesleepcount
    global bucle
    url = "https://www.virustotal.com/api/v3/files"
    files = {"file": open(file, "rb")}
    headers = {
        "accept": "application/json",
        "x-apikey": "206706e5d63a9393a5786e3191ba9c471dcbb00305f4a32d49de38c45f20c4c7"
    }
    response = requests.post(url, files=files, headers=headers)
    if(response.status_code == 429):
        print("Error de cuota excedida")
        print("Codigo de error : " + str(response.status_code))
        pause()
        id = obtener_id(ruta)
        return id
    if response.status_code == 200:
        jsonresp = response.json()
        id = jsonresp.get("data").get("id")
        return id
    else:
        print ("No s'ha pogut obtenir la URL :(")
        print ("ERROR al pujar el archiu :!")
        print ("Status code: " + str(response.status_code))
        exit()

#Definimos la función que va a enviar y recoger el id del archivo >32
def obtener_id32(file):
    files = {"file": open(file, "rb")}
    url = "https://www.virustotal.com/api/v3/files/upload_url"
    headers = {
        "accept": "application/json",
        "x-apikey": "206706e5d63a9393a5786e3191ba9c471dcbb00305f4a32d49de38c45f20c4c7"
    }

    response = requests.get(url, headers=headers)
    if response.status_code == 429:
        print("Error de cuota excedida :! o Error de demasiadas solicitudes controlate ;)")
        print("Codigo de error : " + str(response.status_code))
        time.sleep(60)
        return obtener_id32(file)

    if response.status_code == 200:
        result = response.json()
        url_upload = result.get("data")

    else:
        print("No se ha podido obtener la URL :(")
        print("ERROR al subir el archivo :!")
        print("Status code: " + str(response.status_code))
        return None

    # Obtenemos una ID
    response = requests.post(url_upload, files=files, headers=headers)
    if response.status_code == 429:
        print("Error de cuota excedida :! o Error de demasiadas solicitudes controlate ;)")
        print("Codigo de error : " + str(response.status_code))
        exit()

    if response.status_code == 200:
        result = response.json()
        id = result.get("data").get("id")
        return id
    else:
        print("No se ha podido obtener la ID :(")
        print("Status code: " + str(response.status_code))
        return None


#Definimos la función que va recuperar el array de los archivos de la carpeta
def recorrer_carpeta (carpeta):
    rutas = []
    archivos = []
    for nombre_archivo in os.listdir(carpeta):
        archivos.append(nombre_archivo)
        ruta = os.path.join(carpeta, nombre_archivo)
        if os.path.isfile(ruta):
            rutas.append(ruta)
    return [rutas, archivos]

#Definimos la función que va a comprobar si un archivo es mayor que 32MB
def comprobar_tamaño(ruta_archivo):
    tamano_minimo = 32 * 1024 * 1024  # 32 MB en bytes
    if os.path.isfile(ruta_archivo):
        tamano_archivo = os.path.getsize(ruta_archivo)
        if tamano_archivo >= tamano_minimo:
            return True

def mover(carpeta_origen, carpeta_destino):
    # Comprobar si la carpeta de destino existe, si no, crearla
    if not os.path.exists(carpeta_destino):
        os.makedirs(carpeta_destino)

    # Para cada archivo que se encuentre en la carpeta origen
    for archivo in os.listdir(carpeta_origen):
        ruta_origen = os.path.join(carpeta_origen, archivo)
        ruta_destino = os.path.join(carpeta_destino, archivo)
        
        # Comprobar si el archivo ya existe en la carpeta de destino
        if os.path.exists(ruta_destino):
            # Eliminar el archivo de la carpeta de origen
            os.remove(ruta_origen)
        else:
            # Mover el archivo a la carpeta de destino
            shutil.move(ruta_origen, ruta_destino)

#Definimos la función que va hacer una pausa de 60 segundos
def pause():
    segundos = 0
    while segundos < 60:
        print(segundos)
        segundos += 1
        time.sleep(1)

#Definimos la función para analizar la id
def analizar(id):
    global bucle
    global timesleepcount
    url = "https://www.virustotal.com/api/v3/analyses/"+id
    headers = {
        "accept": "application/json",
        "x-apikey": "206706e5d63a9393a5786e3191ba9c471dcbb00305f4a32d49de38c45f20c4c7"
    }
    response = requests.get(url, headers=headers)
    if(response.status_code == 429):
        print("Error de cuota excedida :! o Error de demasiadas solicitudes controlate ;)")
        print("Codigo de error : " + str(response.status_code))
        result = analizar(id)
        return result
    if response.status_code == 200:
        #print(response.text)
        jsonresp = response.json()
        if jsonresp.get("data").get("attributes").get("status") != "queued":  
            malget = jsonresp.get("data").get("attributes").get("stats").get("malicious")
            #print (malget)
            if  malget>0:
                print('Archivo malicioso detectado!')
                #Determinem result = 1 (virus)
                result = 1
                return result
            else:
                #Determinem result = 0 (freevir)
                result = 0
                return result
        else:
            print ("No s'ha pogut obtenir la URL :(")
            print ("ERROR al pujar el archiu :!")
            print ("Status code: " + str(response.status_code))

#Definimos la función para guardar en la base de datos
def sql(result, archivo, fkusb):
    if result == 1:
        mycursor = mydb.cursor()
        sql = "INSERT INTO cuarentena (path, filename, usbFor) VALUES (%s, %s, %s)"
        val = (file_result1, archivo, fkusb)
        mycursor.execute(sql, val)
        mydb.commit()
    else:   
        mycursor = mydb.cursor()
        sql = "INSERT INTO archivos (path, filename, usbFor) VALUES (%s, %s, %s)"
        val = (file_result0,archivo, fkusb)
        mycursor.execute(sql, val)
        mydb.commit()

def logs(option, ruta):
    if option == 1:
        with open(file_log, "a") as fp:
            fp.write(f"{datetime.date.today()} obteniendo id: {ruta}")
    if option == 2:
        with open(file_log, "a") as fp:
            fp.write(f"{datetime.date.today()} Registro añadido: {ruta}")
    if option == 3:
        with open(file_log, "a") as fp:
            fp.write(f"{datetime.date.today()} Virus encontrado: {ruta}")

def obtener_id_serial_short(dispositivo):
    context = pyudev.Context()
    device = pyudev.Devices.from_device_file(context, dispositivo)
    return device.get('ID_SERIAL_SHORT')

def consultar_id(id_serial_short):
    mycursor = mydb.cursor()
    sql = "SELECT id FROM dispositivos WHERE serial LIKE (%s)"
    val = (id_serial_short,)  # Agrega una coma para crear una tupla de un solo elemento
    mycursor.execute(sql, val)
    id_result = mycursor.fetchone()  # Obtén el resultado de la consulta
    if id_result:
        print (id_result[0])
        return id_result[0]  # Devuelve el primer elemento del resultado (id)
    else:
        return None  # Si no se encontró ningún resultado, devuelve None



#PROGRAMA PRINCIPAL
id_serial_short = obtener_id_serial_short('/dev/sda')
fkusb = consultar_id(id_serial_short)
print ("variable fkusb: {fkusb}")
foranea = fkusb
copiar(file_usb,file_temp)
rutas = []
archivos = []
resultados = recorrer_carpeta(file_temp)
for resultado in resultados:
    print (resultado)
rutas = resultados[0]
archivos = resultados[1]
posicion = 0
for ruta in rutas:
        if comprobar_tamaño (ruta):
            logs(1,ruta)
            id = obtener_id(ruta)
            result = analizar(id)
            if result == 1:
                mover(file_temp,file_result1)
                sql(result,archivos[posicion], foranea)
                logs(3,ruta)
            else:
                mover(file_temp, file_result0) 
                sql(result,archivos[posicion],foranea)
                logs(2,ruta)
        else:
            logs(1,ruta)
            id = obtener_id32(ruta)
            result = analizar(id)
            sql(result,archivos[posicion],foranea)
            logs(2,ruta)
        posicion=posicion+1
