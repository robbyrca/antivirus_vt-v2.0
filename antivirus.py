#Importamos las librerias necesarias para el proyecto
import shutil,os,json, time, datetime
#import mysql.connector, requests
from urllib import response
from pathlib import Path

#Determinamos las rutas
file_here = '/'
file_temp = '/temp'
file_quarantine = '/cuarentena'
file_revised = '/revisado'

def copiar(carpeta_origen, carpeta_desti):
    # Comprovar si la carpeta de desti existeix, si no, crear-la
    if not os.path.exists(carpeta_desti):
        os.makedirs(carpeta_desti)

    # Per a cada carpeta, subcarpeta i fitxer que es trobi a la carpeta origen
    for carpeta, subcarpetes, fitxers in os.walk(carpeta_origen):
        for fitxer in fitxers:
            # Obtenir la ruta completa del fitxer
            ruta_completa = os.path.join(carpeta, fitxer)
            # Copiar el fitxer a la carpeta de desti
            shutil.copy(ruta_completa, carpeta_desti)

#Definimos la variable que va revisar la existencia de archivos en la ruta
def checkFileExistance(enviocheck):
    try:
        with open(enviocheck, 'r') as f:
            return True
    except FileNotFoundError as e:
        return False
    except IOError as e:
        return False


def obtener_id(file):
    global timesleepcount
    global bucle
    url = "https://www.virustotal.com/api/v3/files"
    files = {"file": open(file, "rb")}
    headers = {
        "accept": "application/json",
        "x-apikey": "206706e5d63a9393a5786e3191ba9c471dcbb00305f4a32d49de38c45f20c4c7"
    }
    timesleepcount = timesleepcount + 1
    if timesleepcount == 5:
        print('Control de tiempo de 60 segundos')
        time.sleep(60)
        timesleepcount=0
    else:
        response = requests.post(url, files=files, headers=headers)
        if(response.status_code == 429):
            print("Error de cuota excedida :! o Error de demasiadas solicitudes controlate ;)")
            print("Codigo de error : " + str(response.status_code))
            exit()
        if response.status_code == 200:
            jsonresp = response.json()
            idget = jsonresp.get("data").get("id")
        else:
            print ("No s'ha pogut obtenir la URL :(")
            print ("ERROR al pujar el archiu :!")
            print ("Status code: " + str(response.status_code))

def obtener_id32(file):
        global timesleepcount
        global buclebig
        files = {"file": open(file, "rb")}
        url = "https://www.virustotal.com/api/v3/files/upload_url"
        headers = {
            "accept": "application/json",
            "x-apikey": "206706e5d63a9393a5786e3191ba9c471dcbb00305f4a32d49de38c45f20c4c7"
        }
        timesleepcount = timesleepcount + 1
        if timesleepcount == 5:
            print('Control de tiempo de 60 segundos')
            time.sleep(60)
            timesleepcount=0

        else:
            response = requests.get(url, headers=headers)
            if(response.status_code == 429):
                print("Error de cuota excedida :! o Error de demasiadas solicitudes controlate ;)")
                print("Codigo de error : " + str(response.status_code))
                exit()

            if response.status_code == 200:
                result = response.json()
                url_upload = result.get("data")

            else:
                print ("No s'ha pogut obtenir la URL :(")
                print ("ERROR al pujar el archiu :!")
                print ("Status code: " + str(response.status_code))
        
            #Obtenim una id
            response = requests.post(url_upload, files=files, headers=headers)
            if(response.status_code == 429):
                print("Error de cuota excedida :! o Error de demasiadas solicitudes controlate ;)")
                print("Codigo de error : " + str(response.status_code))
                exit()

            if response.status_code == 200:
                result = response.json()
                idbig = result.get("data").get("id")


    
copiar('/Users/ruben/Documents/Audiolibros','/Users/ruben/Documents/pruebita')